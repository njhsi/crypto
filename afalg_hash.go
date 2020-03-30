package crypto 

import "os"
import "io"
//import "runtime"
//import "crypto/sha256"
import "golang.org/x/sys/unix"
import "github.com/restic/restic/internal/debug"

type AfSHA256Hash struct {
	addr *unix.SockaddrALG
	afd int
	apifd uintptr 
}

func NewAfSHA256HashX() ( *AfSHA256Hash) {
  h,_ := NewAfSHA256Hash()
  return h
}

func NewAfSHA256Hash() ( *AfSHA256Hash, error) {

        afd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
        if err != nil {
                debug.Log("NewAfSHA256Hash:afd socket failed: %v\n",err)
                return nil,err
        }

        addr := &unix.SockaddrALG{
                Type: "hash",
                Name: "sha256",
        }

        err = unix.Bind(afd, addr)
        if err != nil {
                debug.Log("NewAfSHA256Hash:afd bind failed:%d %v\n",afd,err)
                unix.Close(afd)
                return nil, err
        }

	apifd, _, errapifd := unix.Syscall(unix.SYS_ACCEPT, uintptr(afd), 0, 0)
        if errapifd != 0 {
           debug.Log("NewAfSHA256Hash: apifd accept failed: afd=%d, apifd=%d, err=%v\n", afd, int(apifd), errapifd)
           unix.Close(afd)
	   return nil,errapifd
        }

        debug.Log("NewAfSHA256Hash: afd=%d apifd=%d\n",afd, apifd)
        h := &AfSHA256Hash{addr, afd, apifd} //todo: finalizer
	return h, nil

}
func (h *AfSHA256Hash) Size() int { return 32 }
func (h *AfSHA256Hash) BlockSize() int { return 64 }
func (h *AfSHA256Hash) Close() {
	unix.Close(h.afd)
	unix.Close(int(h.apifd))
}
func (h *AfSHA256Hash) Write(p []byte) (n int, err error) {
 	n, err = len(p), unix.Sendto(int(h.apifd), p, unix.MSG_MORE, h.addr)
 	if err !=nil {
	  n=0
	  debug.Log("Write: failed err=%v p=%x\n", err, p[:8])
	}
 	return n, err
}
func (h *AfSHA256Hash) Sum(in []byte) []byte  {
	digest := make([]byte,32)
	// Make a copy of d so that caller can keep writing and summing.
	hashfd0, _, _ := unix.Syscall(unix.SYS_ACCEPT, h.apifd, 0, 0)
	defer unix.Close(int(hashfd0))
	n,err := unix.Read(int(hashfd0),digest)
	if n!=32 || err!=nil {
	   debug.Log("Sum: read failed apifd=%d: n=%d err=%v\n",h.apifd,n,err)
	   return in
	}
	return append(in,digest[:]...)
}
func (h *AfSHA256Hash) Reset() {
	digest := make([]byte,32)
	unix.Read(int(h.apifd),digest)
}


func main_() {
h,_ := NewAfSHA256Hash()
f, _ := os.Open("/etc/dnsmasq.d/conf.d/adb_list.overall")
b := make([]byte, 4096*4)
for {
    n, err := f.Read(b)
    if err == io.EOF {
        break
    }

 n2,err2 := h.Write(b[:n])
 debug.Log("write: n=%d n2=%d err=%v", n, n2, err2)
 digest:=h.Sum(nil)
 debug.Log("sum:%x",digest)
}

unix.Close(h.afd)

}


