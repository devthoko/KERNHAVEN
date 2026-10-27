package compose

import (
	"fmt"
	"regexp"
	"strings"
)

var varNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// interpolate replaces $NAME, ${NAME}, ${NAME:-default}, ${NAME-default},
// ${NAME:?message}, ${NAME?message} and $$ from vars.
func interpolate(s string, vars map[string]string) (string, error) {
	if !strings.Contains(s, "$") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return "", fmt.Errorf("unterminated ${ in %q", s)
			}
			expr := s[i+2 : i+end]
			v, err := expand(expr, vars)
			if err != nil {
				return "", err
			}
			b.WriteString(v)
			i += end + 1
			continue
		}
		name := varNameRe.FindString(s[i+1:])
		if name == "" {
			return "", fmt.Errorf("invalid variable reference in %q (use $$ for a literal $)", s)
		}
		v, ok := vars[name]
		if !ok {
			return "", fmt.Errorf("variable %s is not set", name)
		}
		b.WriteString(v)
		i += 1 + len(name)
	}
	return b.String(), nil
}

func expand(expr string, vars map[string]string) (string, error) {
	name := varNameRe.FindString(expr)
	if name == "" {
		return "", fmt.Errorf("invalid variable expression ${%s}", expr)
	}
	rest := expr[len(name):]
	v, set := vars[name]
	switch {
	case rest == "":
		if !set {
			return "", fmt.Errorf("variable %s is not set", name)
		}
		return v, nil
	case strings.HasPrefix(rest, ":-"):
		if !set || v == "" {
			return rest[2:], nil
		}
		return v, nil
	case strings.HasPrefix(rest, "-"):
		if !set {
			return rest[1:], nil
		}
		return v, nil
	case strings.HasPrefix(rest, ":?"):
		if !set || v == "" {
			return "", fmt.Errorf("variable %s is required: %s", name, rest[2:])
		}
		return v, nil
	case strings.HasPrefix(rest, "?"):
		if !set {
			return "", fmt.Errorf("variable %s is required: %s", name, rest[1:])
		}
		return v, nil
	}
	return "", fmt.Errorf("unsupported variable expression ${%s}", expr)
}
