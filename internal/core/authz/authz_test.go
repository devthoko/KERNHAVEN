package authz

import "testing"

func TestRolePermissionMatrix(t *testing.T) {
	want := map[Permission][]Role{
		SelfManage:        {Owner, Admin, Operator, Viewer},
		SystemRead:        {Owner, Admin, Operator, Viewer},
		UsersRead:         {Owner, Admin},
		UsersManage:       {Owner, Admin},
		SessionsManage:    {Owner},
		AuditRead:         {Owner, Admin},
		JobsRead:          {Owner, Admin, Operator, Viewer},
		JobsManage:        {Owner, Admin, Operator},
		ContainersRead:    {Owner, Admin, Operator, Viewer},
		ContainersOperate: {Owner, Admin, Operator},
		ContainersManage:  {Owner, Admin},
		PolicyExceptions:  {Owner},
		AppsRead:          {Owner, Admin, Operator, Viewer},
		AppsManage:        {Owner, Admin},
		CatalogManage:     {Owner},
		StorageRead:       {Owner, Admin, Operator},
		StorageManage:     {Owner, Admin},
		FilesRead:         {Owner, Admin, Operator},
		FilesWrite:        {Owner, Admin},
		SecurityManage:    {Owner},
	}
	for p, roles := range want {
		granted := map[Role]bool{}
		for _, r := range roles {
			granted[r] = true
		}
		for _, r := range Roles() {
			if r.Has(p) != granted[r] {
				t.Errorf("%s.Has(%s) = %v, want %v", r, p, r.Has(p), granted[r])
			}
		}
	}
}

func TestUnknownRoleGrantsNothing(t *testing.T) {
	r := Role("root")
	if r.Valid() || r.Has(SystemRead) || len(r.Permissions()) != 0 {
		t.Fatal("unknown role must grant nothing")
	}
	if Known("everything") {
		t.Fatal("unknown permission reported as known")
	}
}

func TestCanManage(t *testing.T) {
	cases := []struct {
		actor, target Role
		want          bool
	}{
		{Owner, Owner, true}, {Owner, Admin, true}, {Owner, Viewer, true},
		{Admin, Owner, false}, {Admin, Admin, false}, {Admin, Operator, true}, {Admin, Viewer, true},
		{Operator, Viewer, false}, {Viewer, Viewer, false},
		{Owner, Role("x"), false},
	}
	for _, c := range cases {
		if got := CanManage(c.actor, c.target); got != c.want {
			t.Errorf("CanManage(%s, %s) = %v, want %v", c.actor, c.target, got, c.want)
		}
	}
}
