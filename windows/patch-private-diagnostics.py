"""Remove configuration contents from the pinned Windows shared diagnostics."""
from pathlib import Path
import sys


def apply(root: Path) -> None:
    root = root.resolve(strict=True)
    vendor = root / 'vendor/github.com/amnezia-vpn/amneziawg-windows/v3'
    parser = vendor / 'conf/parser.go'
    scripts = vendor / 'tunnel/scriptrunner.go'
    for path in (parser, scripts):
        assert path.is_file() and not path.is_symlink()
        assert path.resolve().is_relative_to(root)

    text = parser.read_text(encoding='utf-8')
    before = 'return l18n.Sprintf("%s: %q", e.why, e.offender)'
    assert text.count(before) == 1, 'Unexpected pinned config parser'
    text = text.replace(before, 'return e.why // Configuration values must not enter shared diagnostics.')
    parser.write_text(text, encoding='utf-8', newline='\n')

    text = scripts.read_text(encoding='utf-8')
    replacements = {
        '\t"bufio"\n': '\t"io"\n',
        'log.Printf("Skipping execution of script, because dangerous script execution is safely disabled: %#q", command)':
            'log.Print("Skipping disabled tunnel script")',
        'log.Printf("Executing: %#q", command)': 'log.Print("Executing tunnel script")',
        '\t\tscanner := bufio.NewScanner(reader)\n\t\tfor scanner.Scan() {\n\t\t\tlog.Printf("cmd> %s", scanner.Text())\n\t\t}':
            '\t\t// Drain the pipe without persisting private command output.\n\t\t_, _ = io.Copy(io.Discard, reader)',
    }
    for before, after in replacements.items():
        assert text.count(before) == 1, 'Unexpected pinned script diagnostics'
        text = text.replace(before, after)
    assert 'conf.AdminBool("DangerousScriptExecution")' in text
    assert 'fmt.Sprintf("cmd /c %s", command)' in text
    assert 'state.ExitCode()' in text
    assert 'scanner.Text()' not in text and 'log.Printf("Executing:' not in text
    scripts.write_text(text, encoding='utf-8', newline='\n')


if __name__ == '__main__':
    assert len(sys.argv) == 2
    apply(Path(sys.argv[1]))
    print('Pinned configuration and script diagnostics use status-only messages')
