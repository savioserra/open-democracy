package bill

import (
    "fmt"
    "strings"

    "github.com/hyperledger/fabric-chaincode-go/pkg/cid"
    "github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// Known authority roles encoded in scope claims (final segment)
// Maps role token to bitwise Role value
var authorityRoles = map[string]Role{
    "ADMIN":    RoleAdmin,
    "PROPOSER": RoleProposer,
    "EDITOR":   RoleEditor,
    "VOTER":    RoleVoter,
    "AUDITOR":  RoleAuditor,
}

// Invoker encapsulates transaction invoker identity and attributes.
// It provides utility methods for RBAC and hierarchical scope checks.
type Invoker struct {
    ctx    contractapi.TransactionContextInterface
    ID     string
    // Claims maps (bitwise) Role -> list of scope patterns (uppercase) where the role applies.
    Claims map[Role][]string
    // Scopes holds scope-only patterns (role stripped) for general InScope checks.
    Scopes []string
}

// GetInvoker builds an Invoker from the transaction context attributes.
// It reads attributes "scope" and "scopes" (CSV). Each entry can be either a plain scope
// (e.g., "ES:TEACHER_UNION:DIVISION_2:*") or a scope with role suffix (e.g., "ES:...:ADMIN").
// If the last segment matches a known role token, it is treated as the role; otherwise it's a plain scope.
func GetInvoker(ctx contractapi.TransactionContextInterface) (*Invoker, error) {
    id, err := cid.GetID(ctx.GetStub())
    if err != nil {
        return nil, fmt.Errorf("failed to get invoker ID: %w", err)
    }
    scopeAttr, _, _ := cid.GetAttributeValue(ctx.GetStub(), "scope")
    scopesAttr, _, _ := cid.GetAttributeValue(ctx.GetStub(), "scopes")

    claims := map[Role][]string{}
    scopes := make([]string, 0)

    addClaim := func(raw string) {
        raw = strings.TrimSpace(raw)
        if raw == "" {
            return
        }
        up := normalizeScopePattern(raw)
        parts := splitScopePath(up)
        if len(parts) == 0 {
            return
        }
        last := parts[len(parts)-1]
        if roleBit, ok := authorityRoles[last]; ok {
            scopeOnly := strings.Join(parts[:len(parts)-1], ":")
            if scopeOnly != "" {
                claims[roleBit] = uniqueAppend(claims[roleBit], scopeOnly)
                scopes = uniqueAppend(scopes, scopeOnly)
            }
            return
        }
        // plain scope pattern
        scopes = uniqueAppend(scopes, up)
    }

    if s := strings.TrimSpace(scopeAttr); s != "" {
        addClaim(s)
    }
    for _, s := range splitCSV(scopesAttr) {
        addClaim(s)
    }

    return &Invoker{
        ctx:    ctx,
        ID:     id,
        Claims: claims,
        Scopes: scopes,
    }, nil
}

// HasRole checks if invoker has a per-bill Role mask.
func (i *Invoker) HasRole(b *Bill, role Role) bool {
    if i == nil || b == nil {
        return false
    }
    mask := b.Roles[i.ID]
    return mask.Has(role)
}

// HasRoleInScope returns true if the invoker has the given ROLE at or above the required scope.
func (i *Invoker) HasRoleInScope(role Role, requiredScope string) bool {
    if i == nil {
        return false
    }
    req := normalizeScopePattern(requiredScope)
    patterns := i.Claims[role]
    if len(patterns) == 0 {
        return false
    }
    // Empty required scope means any scope
    if req == "" {
        return true
    }
    for _, p := range patterns {
        if scopeCovers(p, req) {
            return true
        }
    }
    return false
}

// HasAnyRole returns true if the invoker has at least one claim for the given role (any scope).
func (i *Invoker) HasAnyRole(role Role) bool {
    if i == nil {
        return false
    }
    return len(i.Claims[role]) > 0
}

// HasAnyAdmin returns true if the invoker has ADMIN in any scope.
func (i *Invoker) HasAnyAdmin() bool { return i.HasAnyRole(RoleAdmin) }

// HasAdminFor returns true if the invoker has ADMIN authority at or above the required scope.
func (i *Invoker) HasAdminFor(requiredScope string) bool {
    req := normalizeScopePattern(requiredScope)
    if req == "" {
        return i.HasAnyAdmin()
    }
    return i.HasRoleInScope(RoleAdmin, req)
}

// InScope checks if invoker belongs to (or is above) the required hierarchical scope.
// Scope pattern uses ':' as the hierarchy separator and '*' wildcard per segment.
// Example: required "ES:TEACHER_UNION:DIVISION_2:*" will be satisfied by an invoker with
// scopes like "ES:*" or "ES:TEACHER_UNION:*" or the exact required one.
func (i *Invoker) InScope(required string) bool {
    if i == nil {
        return false
    }
    req := normalizeScopePattern(required)
    if req == "" {
        return true // open scope
    }
    if len(i.Scopes) == 0 {
        return false
    }
    for _, s := range i.Scopes {
        if scopeCovers(s, req) {
            return true
        }
    }
    return false
}

// normalizeScopePattern uppercases and trims a scope pattern.
func normalizeScopePattern(s string) string {
    return strings.ToUpper(strings.TrimSpace(s))
}

func splitScopePath(s string) []string {
    s = normalizeScopePattern(s)
    if s == "" {
        return []string{}
    }
    parts := strings.Split(s, ":")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p != "" {
            out = append(out, p)
        }
    }
    return out
}

// scopeCovers returns true if the actorPattern is at the same or higher level than the requiredPattern
// and matches it by prefix, supporting '*' wildcard in either pattern to match the remainder.
// This enables higher-hierarchy peers (shorter prefix) to act on lower-level scopes, but not vice‑versa.
func scopeCovers(actorPattern, requiredPattern string) bool {
    a := splitScopePath(actorPattern)
    r := splitScopePath(requiredPattern)
    if len(r) == 0 {
        return true
    }
    i := 0
    for i < len(a) && i < len(r) {
        if a[i] == "*" || r[i] == "*" {
            return true
        }
        if a[i] != r[i] {
            return false
        }
        i++
    }
    // Actor covers required when actor is shorter or equal after matching all compared segments
    if i == len(a) && i <= len(r) {
        return true
    }
    return false
}
