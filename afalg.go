package crypto 


import (
//	"golang.org/x/crypto/chacha20"
	"fmt"
//	"os"
	"unsafe"
//	"bufio"
//	"io"
	"sync"
	"encoding/hex"
	"github.com/restic/restic/internal/debug"
	"golang.org/x/sys/unix"
	"runtime"
)

type af_alg_iv struct {
	ivlen uint32
	iv    [32]byte
}


type Crypter struct {
  key    []byte
//  iv     []byte

  afd	int
  apifd uintptr  
}

type repository struct {
	items map[string]int
	mu    sync.RWMutex
}
func (r *repository) Set(key string, data int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[key] = data
}
func (r *repository) Get(key string) (int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.items[key]
	if !ok {
		return -1, fmt.Errorf("The '%s' is not presented", key)
	}
	return item, nil
}
var (
	repo_    *repository
	once_ sync.Once
)

func Repository() *repository {
	once_.Do(func() {
		repo_ = &repository{ items: make(map[string]int),}
		runtime.SetFinalizer(repo_, func(r *repository) {
			debug.Log("repository finalizer: do cleanup\n")
			r.mu.Lock()
		        defer r.mu.Unlock()
			for key,afd := range r.items {
			    err := unix.Close(afd)
			    debug.Log("repository finalizer: close afd=%d for key=%x\n",afd,key,err)			    
			}
			r.items=make(map[string]int)
		})
	})
	
	return repo_
}


func NewCrypter(key []byte ) (*Crypter, error) {
	debug.Log("NewCrypter: key len=%d, %x \n", len(key), key[:8])

   skey := hex.EncodeToString(key)
   repo := Repository()

   afd, err := repo.Get(skey)
   if err!=nil || afd<0 {
        afd, err = unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		debug.Log("NewCrypter:afd socket failed:%d %v %x\n",afd,err,key[:8])
		return nil,err
	}

	addr := &unix.SockaddrALG{
		Type: "skcipher",
		Name: "xchacha20",
	}

	err = unix.Bind(afd, addr)
	if err != nil {
		debug.Log("NewCrypter:afd bind failed:%d %v %x\n",afd,err,key[:8])
		unix.Close(afd)
		return nil, err
	}

	err = unix.SetsockoptString(afd, unix.SOL_ALG, unix.ALG_SET_KEY, string(key))
	if err != nil {
		debug.Log("NewCrypter:afd setsocketopt failed:%d %v %x\n",afd,err,key[:8])
		unix.Close(afd)
		return nil,err
	}
    
        repo.Set(skey,afd)
     } else {
       debug.Log("NewCrypter: found existed afd=%d for key=%x\n", afd,key[:8])
     }
  

	apifd, _, errapifd := unix.Syscall(unix.SYS_ACCEPT, uintptr(afd), 0, 0)
	if errapifd != 0 {
	   debug.Log("NewCrypter: apifd accept failed: key=%x, afd=%d, apifd=%d, err=%v\n",key[:8], afd, int(apifd), errapifd)
	   return nil,errapifd
	}

	debug.Log("NewCrypter:key=%x afd=%d apifd=%d\n",key,afd, apifd)
	return &Crypter{key, afd, apifd}, nil
}	


func (c *Crypter) Encrypt(out []byte, input []byte, nonce []byte) (n int, err error) {
	return c.Xcrypt(unix.ALG_OP_ENCRYPT, out, input, nonce) 
}

func (c *Crypter) Decrypt(out []byte, input []byte, nonce []byte) (n int, err error) {
	return c.Xcrypt(unix.ALG_OP_DECRYPT, out, input, nonce)
}

func (c *Crypter) Xcrypt(mode uint32,out []byte, input []byte, nonce []byte) (n int, err error) {
	debug.Log("Xcrypt mode=%d: ciphertext len %d, iv len %d", mode, len(input), len(nonce))
        var iv [32]byte = [32]byte{0}
        copy(iv[:],nonce)

        n=0
	STEP:=4096*4
	for {
	   count,bs,be :=0, n, n+STEP
           if be>len(input) {
              be=len(input)
           }
	   count,err = CryptoAPI(out[bs:be], c.apifd, mode, iv[:], input[bs:be])
	   n=n+count
	   if err!=nil || n>=len(input) { break }
	}

        if err != nil || n!=len(input) {
               debug.Log("Decrypt mode=%d: n=%d, err=%v\n",mode,n,err) 
        }
	defer unix.Close(int(c.apifd))
        return n,err 
}

func CryptoAPI(out []byte, fd uintptr, mode uint32, iv []byte, input []byte) (n int, err error) {
//	api := os.NewFile(fd, "CryptoAPI")
	cmsg := BuildCmsg(mode, iv)

	err = unix.Sendmsg(int(fd), input, cmsg, nil, 0)
	if err != nil {
		debug.Log("CryptoAPI: sendmsg failed: input=%x, iv=%x, fd=%d, err=%v\n",input[:8],iv[:8], int(fd),err)
		return 0,err
	}

	n, err = unix.Read(int(fd),out)
  	if  n!=len(input) {
	        debug.Log("CryptoAPI: read failed: input=%x, iv=%x, fd=%d, n=%d err=%v\n",input[:8],iv[:8], int(fd),n, err)
                return n,err
        }

	return n,err
}

func BuildCmsg(mode uint32, iv []byte) []byte {
	cbuf := make([]byte, unix.CmsgSpace(4)+unix.CmsgSpace(36))

	cmsg := (*unix.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	cmsg.Level = unix.SOL_ALG
	cmsg.Type = unix.ALG_SET_OP
	cmsg.SetLen(unix.CmsgLen(4))

	op := (*uint32)(unsafe.Pointer(CMSG_DATA(cmsg)))
	*op = mode

	cmsg = (*unix.Cmsghdr)(unsafe.Pointer(&cbuf[unix.CmsgSpace(4)]))
	cmsg.Level = unix.SOL_ALG
	cmsg.Type = unix.ALG_SET_IV
	cmsg.SetLen(unix.CmsgLen(36))

	alg_iv := (*af_alg_iv)(unsafe.Pointer(CMSG_DATA(cmsg)))
	alg_iv.ivlen = uint32(len(iv))
	copy(alg_iv.iv[:], iv)

	return cbuf
}

func CMSG_DATA(cmsg *unix.Cmsghdr) unsafe.Pointer {
	return unsafe.Pointer(uintptr(unsafe.Pointer(cmsg)) + uintptr(unix.SizeofCmsghdr))
}
