//go:build windows && r013_acl_fixture

// SPDX-License-Identifier: MIT
// Hosted, disposable CI only. Never run against a machine containing VPN013 data.
package r013acl

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const aclPurpose = "VPN013-CI-ACL-SYNTHETIC"
const aclPlain = "synthetic-test-only-no-customer-data"
const aclMarker = ".r013-ci-owned"
const aclCipher = "synthetic.dpapi"

type aclReceipt struct {
	Role  string `json:"role"`
	SID   string `json:"sid"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	DACL  string `json:"dacl,omitempty"`
}
type aclService struct{ role, root, nonce, receipt string }

func TestMain(m *testing.M) {
	if len(os.Args) == 7 && os.Args[1] == "--r013-acl-service" {
		service, e := svc.IsWindowsService()
		role, name, root, nonce, receipt := os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6]
		if e != nil || !service || (role != "system" && role != "localservice") || !strings.HasPrefix(name, "R013AclCI-") || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(nonce) || !filepath.IsAbs(root) || !filepath.IsAbs(receipt) {
			os.Exit(31)
		}
		if svc.Run(name, &aclService{role, root, nonce, receipt}) != nil {
			os.Exit(32)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func (s *aclService) Execute(_ []string, _ <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running}
	r := aclReceipt{Role: s.role}
	e := s.run(&r)
	r.OK = e == nil
	if e != nil {
		r.Error = e.Error()
	}
	b, _ := json.Marshal(r)
	if os.WriteFile(s.receipt, b, 0600) != nil {
		return true, 33
	}
	changes <- svc.Status{State: svc.StopPending}
	if e != nil {
		return true, 34
	}
	return false, 0
}
func (s *aclService) run(r *aclReceipt) error {
	var token windows.Token
	if e := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &token); e != nil {
		return e
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		return e
	}
	r.SID = user.User.Sid.String()
	expected := "S-1-5-18"
	if s.role == "localservice" {
		expected = "S-1-5-19"
	}
	if r.SID != expected {
		return errors.New("unexpected service identity")
	}
	pf, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if e != nil {
		return e
	}
	if !strings.EqualFold(s.root, filepath.Join(pf, "VPN013 WG")) {
		return errors.New("unexpected root")
	}
	b, e := os.ReadFile(filepath.Join(s.root, aclMarker))
	if e != nil || string(b) != s.nonce {
		return errors.New("fixture marker mismatch")
	}
	data := filepath.Join(s.root, "Data")
	configs := filepath.Join(data, "Configurations")
	cipher := filepath.Join(configs, aclCipher)
	if s.role == "localservice" {
		_, e = os.ReadFile(cipher)
		if !errors.Is(e, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("local service read must be denied: %v", e)
		}
		f, e := os.OpenFile(filepath.Join(configs, "forbidden.tmp"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if f != nil {
			f.Close()
		}
		if !errors.Is(e, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("local service write must be denied: %v", e)
		}
		return nil
	}
	// Fresh SCM process, actual default root; no PresetRootDirectory.
	actual, e := conf.RootDirectory(true)
	if e != nil {
		return e
	}
	if !strings.EqualFold(actual, data) {
		return errors.New("default root mismatch")
	}
	sd, e := windows.GetNamedSecurityInfo(data, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	expectedSD, e := windows.SecurityDescriptorFromString("O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		return e
	}
	r.DACL = sd.String()
	if r.DACL != expectedSD.String() {
		return errors.New("data security descriptor differs")
	}
	if e = os.Mkdir(configs, 0700); e != nil {
		return e
	}
	enc, e := dpapi.Encrypt([]byte(aclPlain), aclPurpose)
	if e != nil {
		return e
	}
	if strings.Contains(string(enc), aclPlain) {
		return errors.New("plaintext stored")
	}
	if e = os.WriteFile(cipher, enc, 0600); e != nil {
		return e
	}
	read, e := os.ReadFile(cipher)
	if e != nil {
		return e
	}
	plain, e := dpapi.Decrypt(read, aclPurpose)
	if e != nil || string(plain) != aclPlain {
		return errors.New("SYSTEM DPAPI roundtrip failed")
	}
	return nil
}

func createACLReceiptDir(path string) error {
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)")
	if e != nil {
		return e
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	return windows.CreateDirectory(p, &sa)
}
func invokeACLService(t *testing.T, scm *mgr.Mgr, exe, role, root, nonce, dir string) aclReceipt {
	t.Helper()
	name := "R013AclCI-" + role + "-" + nonce
	receipt := filepath.Join(dir, role+".json")
	cfg := mgr.Config{StartType: mgr.StartManual, ServiceType: windows.SERVICE_WIN32_OWN_PROCESS}
	if role == "localservice" {
		cfg.ServiceStartName = `NT AUTHORITY\LocalService`
	}
	s, e := scm.CreateService(name, exe, cfg, "--r013-acl-service", role, name, root, nonce, receipt)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	defer func() {
		s.Control(svc.Stop)
		if e := s.Delete(); e != nil {
			t.Error(e)
		}
	}()
	if e = s.Start(); e != nil {
		t.Fatal(e)
	}
	end := time.Now().Add(30 * time.Second)
	for time.Now().Before(end) {
		st, e := s.Query()
		if e != nil {
			t.Fatal(e)
		}
		if st.State == svc.Stopped {
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	st, e := s.Query()
	if e != nil || st.State != svc.Stopped {
		t.Fatal("fixture service did not stop")
	}
	b, e := os.ReadFile(receipt)
	if e != nil {
		t.Fatal(e)
	}
	var r aclReceipt
	if e = json.Unmarshal(b, &r); e != nil || !r.OK || r.Role != role {
		t.Fatalf("fixture service failed: %+v", r)
	}
	return r
}
func TestDefaultRootDirectoryACLHostedFixture(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" || os.Getenv("RUNNER_OS") != "Windows" || os.Getenv("GITHUB_REPOSITORY") != "2njz45z86r-commits/vpn013-wg-ios" || os.Getenv("R013_DEFAULT_ACL_FIXTURE") != "1" {
		t.Fatal("explicit disposable hosted CI opt-in required")
	}
	sha, run := os.Getenv("GITHUB_SHA"), os.Getenv("GITHUB_RUN_ID")
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(sha) || !regexp.MustCompile(`^[0-9]+$`).MatchString(run) {
		t.Fatal("missing source/run identity")
	}
	pf, e := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(pf, "VPN013 WG")
	var random [16]byte
	if _, e = rand.Read(random[:]); e != nil {
		t.Fatal(e)
	}
	nonce := hex.EncodeToString(random[:])
	// Create exclusively: an existing root is never touched, even on CI.
	if e = os.Mkdir(root, 0700); e != nil {
		t.Fatalf("fixture root must be absent: %v", e)
	}
	marker := filepath.Join(root, aclMarker)
	if e = os.WriteFile(marker, []byte(nonce), 0600); e != nil {
		_ = os.Remove(root)
		t.Fatal(e)
	}
	cleaned := false
	cleanupRoot := func() error {
		b, e := os.ReadFile(marker)
		if e != nil || string(b) != nonce {
			return errors.New("ownership marker changed; cleanup refused")
		}
		for _, p := range []string{filepath.Join(root, "Data", "Configurations", "admin-probe.tmp"), filepath.Join(root, "Data", "Configurations", aclCipher), filepath.Join(root, "Data", "Configurations"), filepath.Join(root, "Data"), filepath.Join(root, "acl-fixture.exe")} {
			if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
				return fmt.Errorf("bounded cleanup %s: %w", filepath.Base(p), e)
			}
		}
		entries, e := os.ReadDir(root)
		if e != nil {
			return e
		}
		if len(entries) != 1 || entries[0].Name() != aclMarker {
			return errors.New("unexpected root contents; marker retained")
		}
		if e = os.Remove(marker); e != nil {
			return e
		}
		if e = os.Remove(root); e != nil {
			return e
		}
		cleaned = true
		return nil
	}
	defer func() {
		if !cleaned {
			if e := cleanupRoot(); e != nil {
				t.Error(e)
			}
		}
	}()
	temp := os.Getenv("RUNNER_TEMP")
	if !filepath.IsAbs(temp) {
		t.Fatal("absolute runner temp required")
	}
	dir := filepath.Join(temp, "r013-acl-"+nonce)
	if e = createACLReceiptDir(dir); e != nil {
		t.Fatal(e)
	}
	defer func() {
		for _, p := range []string{filepath.Join(dir, "system.json"), filepath.Join(dir, "localservice.json"), dir} {
			if e := os.Remove(p); e != nil && !os.IsNotExist(e) {
				t.Errorf("receipt cleanup: %v", e)
			}
		}
	}()
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	binary, e := os.ReadFile(exe)
	if e != nil {
		t.Fatal(e)
	}
	exe = filepath.Join(root, "acl-fixture.exe")
	if e = os.WriteFile(exe, binary, 0600); e != nil {
		t.Fatal(e)
	}
	scm, e := mgr.Connect()
	if e != nil {
		t.Fatal(e)
	}
	defer scm.Disconnect()
	sys := invokeACLService(t, scm, exe, "system", root, nonce, dir)
	// This process must actually hold an enabled Administrators group.
	admin, e := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if e != nil {
		t.Fatal(e)
	}
	var tok windows.Token
	if e = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &tok); e != nil {
		t.Fatal(e)
	}
	var impersonation windows.Token
	e = windows.DuplicateTokenEx(tok, windows.TOKEN_QUERY, nil, windows.SecurityIdentification, windows.TokenImpersonation, &impersonation)
	tok.Close()
	if e != nil {
		t.Fatal(e)
	}
	member, e := impersonation.IsMember(admin)
	impersonation.Close()
	if e != nil || !member {
		t.Fatal("enabled administrators token required")
	}
	configs := filepath.Join(root, "Data", "Configurations")
	if _, e = os.ReadDir(configs); e != nil {
		t.Fatal(e)
	}
	probe := filepath.Join(configs, "admin-probe.tmp")
	if e = os.WriteFile(probe, []byte("synthetic"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(probe); e != nil {
		t.Fatal(e)
	}
	outsider := invokeACLService(t, scm, exe, "localservice", root, nonce, dir)
	if e = cleanupRoot(); e != nil {
		t.Fatal(e)
	}
	proof := map[string]any{"sourceCommit": sha, "runId": run, "fixture": "default-root-directory-acl", "systemSID": sys.SID, "localServiceSID": outsider.SID, "dataSecurityDescriptor": sys.DACL, "systemDPAPIRoundTrip": true, "administratorDirectoryReadWrite": true, "localServiceReadWriteDenied": true, "humanStandardUserTested": false, "customerDataUsed": false}
	b, e := json.MarshalIndent(proof, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	proofFile, e := os.OpenFile(filepath.Join(temp, "r013-default-acl-proof.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = proofFile.Write(b); e != nil {
		proofFile.Close()
		t.Fatal(e)
	}
	if e = proofFile.Close(); e != nil {
		t.Fatal(e)
	}
}
