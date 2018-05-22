package policy

import (
	"fmt"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kapi "k8s.io/kubernetes/pkg/apis/core"

	authorizationapi "github.com/openshift/origin/pkg/authorization/apis/authorization"
	fakeauthorizationclient "github.com/openshift/origin/pkg/authorization/generated/internalclientset/fake"
)

func TestModifyNamedClusterRoleBinding(t *testing.T) {
	tests := map[string]struct {
		action                      string
		inputRole                   string
		inputRoleBindingName        string
		inputSubjects               []string
		expectedRoleBindingName     string
		expectedSubjects            []string
		expectedWarning             string
		existingClusterRoleBindings *authorizationapi.ClusterRoleBindingList
		existingClusterRoles        *authorizationapi.ClusterRoleList
	}{
		// no name provided - create "edit" for role "edit"
		"create-clusterrolebindinge": {
			action:    "add",
			inputRole: "edit",
			inputSubjects: []string{
				"foo",
			},
			expectedRoleBindingName: "edit",
			expectedSubjects: []string{
				"foo",
			},
			expectedWarning: "",
			existingClusterRoleBindings: &authorizationapi.ClusterRoleBindingList{
				Items: []authorizationapi.ClusterRoleBinding{},
			},
			existingClusterRoles: &authorizationapi.ClusterRoleList{
				Items: []authorizationapi.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
				}},
			},
		},
		// name provided - create "custom" for non-existent clusterrole "edit"
		"create-named-clusterrolebinding-nonexistent-role": {
			action:               "add",
			inputRole:            "edit",
			inputRoleBindingName: "custom",
			inputSubjects: []string{
				"foo",
			},
			expectedRoleBindingName: "custom",
			expectedSubjects: []string{
				"foo",
			},
			expectedWarning: "Warning: role 'edit' not found",
			existingClusterRoleBindings: &authorizationapi.ClusterRoleBindingList{
				Items: []authorizationapi.ClusterRoleBinding{},
			},
			existingClusterRoles: &authorizationapi.ClusterRoleList{
				Items: []authorizationapi.ClusterRole{},
			},
		},
		// name provided - create "custom" for existing role "edit"
		"create-named-clusterrolebinding": {
			action:               "add",
			inputRole:            "edit",
			inputRoleBindingName: "custom",
			inputSubjects: []string{
				"foo",
			},
			expectedRoleBindingName: "custom",
			expectedSubjects: []string{
				"foo",
			},
			expectedWarning: "",
			existingClusterRoleBindings: &authorizationapi.ClusterRoleBindingList{
				Items: []authorizationapi.ClusterRoleBinding{},
			},
			existingClusterRoles: &authorizationapi.ClusterRoleList{
				Items: []authorizationapi.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
				}},
			},
		},
		// name provided - modify "custom"
		"update-named-clusterrolebinding": {
			action:               "add",
			inputRole:            "edit",
			inputRoleBindingName: "custom",
			inputSubjects: []string{
				"baz",
			},
			expectedRoleBindingName: "custom",
			expectedSubjects: []string{
				"bar",
				"baz",
			},
			expectedWarning: "",
			existingClusterRoleBindings: &authorizationapi.ClusterRoleBindingList{
				Items: []authorizationapi.ClusterRoleBinding{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
					Subjects: []kapi.ObjectReference{{
						Name: "foo",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name: "edit",
					}}, {
					ObjectMeta: metav1.ObjectMeta{
						Name: "custom",
					},
					Subjects: []kapi.ObjectReference{{
						Name: "bar",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name: "edit",
					}},
				},
			},
			existingClusterRoles: &authorizationapi.ClusterRoleList{
				Items: []authorizationapi.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
				}},
			},
		},
		// name provided - remove from "custom"
		"remove-named-clusterrolebinding": {
			action:               "remove",
			inputRole:            "edit",
			inputRoleBindingName: "custom",
			inputSubjects: []string{
				"baz",
			},
			expectedRoleBindingName: "custom",
			expectedSubjects: []string{
				"bar",
			},
			expectedWarning: "",
			existingClusterRoleBindings: &authorizationapi.ClusterRoleBindingList{
				Items: []authorizationapi.ClusterRoleBinding{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
					Subjects: []kapi.ObjectReference{{
						Name: "foo",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name: "edit",
					}}, {
					ObjectMeta: metav1.ObjectMeta{
						Name: "custom",
					},
					Subjects: []kapi.ObjectReference{
						{Name: "bar", Kind: authorizationapi.UserKind},
						{Name: "baz", Kind: authorizationapi.UserKind},
					},
					RoleRef: kapi.ObjectReference{
						Name: "edit",
					}},
				},
			},
			existingClusterRoles: &authorizationapi.ClusterRoleList{
				Items: []authorizationapi.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
				}},
			},
		},
		// no name provided - creates "edit-0"
		"update-default-clusterrolebinding": {
			action:    "add",
			inputRole: "edit",
			inputSubjects: []string{
				"baz",
			},
			expectedRoleBindingName: "edit-0",
			expectedSubjects: []string{
				"baz",
			},
			expectedWarning: "",
			existingClusterRoleBindings: &authorizationapi.ClusterRoleBindingList{
				Items: []authorizationapi.ClusterRoleBinding{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
					Subjects: []kapi.ObjectReference{{
						Name: "foo",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name: "edit",
					}}, {
					ObjectMeta: metav1.ObjectMeta{
						Name: "custom",
					},
					Subjects: []kapi.ObjectReference{{
						Name: "bar",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name: "edit",
					}},
				},
			},
			existingClusterRoles: &authorizationapi.ClusterRoleList{
				Items: []authorizationapi.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
				}},
			},
		},
		// no name provided - removes "baz"
		"remove-default-clusterrolebinding": {
			action:    "remove",
			inputRole: "edit",
			inputSubjects: []string{
				"baz",
			},
			expectedRoleBindingName: "edit",
			expectedSubjects: []string{
				"foo",
			},
			expectedWarning: "",
			existingClusterRoleBindings: &authorizationapi.ClusterRoleBindingList{
				Items: []authorizationapi.ClusterRoleBinding{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
					Subjects: []kapi.ObjectReference{
						{Name: "foo", Kind: authorizationapi.UserKind},
						{Name: "baz", Kind: authorizationapi.UserKind},
					},
					RoleRef: kapi.ObjectReference{
						Name: "edit",
					}}, {
					ObjectMeta: metav1.ObjectMeta{
						Name:      "custom",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{{
						Name: "bar",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}},
				},
			},
			existingClusterRoles: &authorizationapi.ClusterRoleList{
				Items: []authorizationapi.ClusterRole{{
					ObjectMeta: metav1.ObjectMeta{
						Name: "edit",
					},
				}},
			},
		},
	}
	for tcName, tc := range tests {
		// Set up modifier options and run AddRole()
		o := &RoleModificationOptions{
			RoleName:            tc.inputRole,
			RoleBindingName:     tc.inputRoleBindingName,
			Users:               tc.inputSubjects,
			RoleBindingAccessor: NewClusterRoleBindingAccessor(fakeauthorizationclient.NewSimpleClientset(tc.existingClusterRoleBindings, tc.existingClusterRoles).Authorization()),
		}

		modifyRoleAndCheck(t, o, tcName, tc.action, tc.expectedRoleBindingName, tc.expectedSubjects, tc.expectedWarning)
	}
}

func TestModifyNamedLocalRoleBinding(t *testing.T) {
	tests := map[string]struct {
		action                  string
		inputRole               string
		inputRoleBindingName    string
		inputSubjects           []string
		expectedRoleBindingName string
		expectedSubjects        []string
		expectedWarning         string
		existingRoleBindings    *authorizationapi.RoleBindingList
		existingRoles           *authorizationapi.RoleList
	}{
		// no name provided - create "edit" for role "edit"
		"create-rolebinding": {
			action:    "add",
			inputRole: "edit",
			inputSubjects: []string{
				"foo",
			},
			expectedRoleBindingName: "edit",
			expectedSubjects: []string{
				"foo",
			},
			expectedWarning: "",
			existingRoleBindings: &authorizationapi.RoleBindingList{
				Items: []authorizationapi.RoleBinding{},
			},
			existingRoles: &authorizationapi.RoleList{
				Items: []authorizationapi.Role{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
				}},
			},
		},
		// name provided - create "custom" for role "edit"
		"create-named-binding": {
			action:               "add",
			inputRole:            "edit",
			inputRoleBindingName: "custom",
			inputSubjects: []string{
				"foo",
			},
			expectedRoleBindingName: "custom",
			expectedSubjects: []string{
				"foo",
			},
			expectedWarning: "",
			existingRoleBindings: &authorizationapi.RoleBindingList{
				Items: []authorizationapi.RoleBinding{},
			},
			existingRoles: &authorizationapi.RoleList{
				Items: []authorizationapi.Role{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
				}},
			},
		},
		// name provided - create "custom" for non-existent role "edit" in default namespace
		"create-named-binding-to-nonexistent-role": {
			action:               "add",
			inputRole:            "edit",
			inputRoleBindingName: "custom",
			inputSubjects: []string{
				"foo",
			},
			expectedRoleBindingName: "custom",
			expectedSubjects: []string{
				"foo",
			},
			expectedWarning: "Warning: role 'edit' not found",
			existingRoleBindings: &authorizationapi.RoleBindingList{
				Items: []authorizationapi.RoleBinding{},
			},
			existingRoles: &authorizationapi.RoleList{
				Items: []authorizationapi.Role{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit", // decoy role: same name, wrong namespace
						Namespace: "other",
					},
				}},
			},
		},
		// no name provided - modify "edit"
		"update-default-binding": {
			action:    "add",
			inputRole: "edit",
			inputSubjects: []string{
				"baz",
			},
			expectedRoleBindingName: "edit-0",
			expectedSubjects: []string{
				"baz",
			},
			expectedWarning: "",
			existingRoleBindings: &authorizationapi.RoleBindingList{
				Items: []authorizationapi.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{{
						Name: "foo",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}}, {
					ObjectMeta: metav1.ObjectMeta{
						Name:      "custom",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{{
						Name: "bar",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}},
				},
			},
			existingRoles: &authorizationapi.RoleList{
				Items: []authorizationapi.Role{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
				}},
			},
		},
		// no name provided - remove "bar"
		"remove-default-binding": {
			action:    "remove",
			inputRole: "edit",
			inputSubjects: []string{
				"foo",
			},
			expectedRoleBindingName: "edit",
			expectedSubjects: []string{
				"baz",
			},
			expectedWarning: "",
			existingRoleBindings: &authorizationapi.RoleBindingList{
				Items: []authorizationapi.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{
						{Name: "foo", Kind: authorizationapi.UserKind},
						{Name: "baz", Kind: authorizationapi.UserKind},
					},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}}, {
					ObjectMeta: metav1.ObjectMeta{
						Name:      "custom",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{{
						Name: "bar",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}},
				},
			},
			existingRoles: &authorizationapi.RoleList{
				Items: []authorizationapi.Role{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
				}},
			},
		},
		// name provided - modify "custom"
		"update-named-binding": {
			action:               "add",
			inputRole:            "edit",
			inputRoleBindingName: "custom",
			inputSubjects: []string{
				"baz",
			},
			expectedRoleBindingName: "custom",
			expectedSubjects: []string{
				"bar",
				"baz",
			},
			existingRoleBindings: &authorizationapi.RoleBindingList{
				Items: []authorizationapi.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{{
						Name: "foo",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}}, {
					ObjectMeta: metav1.ObjectMeta{
						Name:      "custom",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{{
						Name: "bar",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}},
				},
			},
			existingRoles: &authorizationapi.RoleList{
				Items: []authorizationapi.Role{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
				}},
			},
		},
		// name provided - modify "custom"
		"remove-named-binding": {
			action:               "remove",
			inputRole:            "edit",
			inputRoleBindingName: "custom",
			inputSubjects: []string{
				"baz",
			},
			expectedRoleBindingName: "custom",
			expectedSubjects: []string{
				"bar",
			},
			expectedWarning: "",
			existingRoleBindings: &authorizationapi.RoleBindingList{
				Items: []authorizationapi.RoleBinding{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{{
						Name: "foo",
						Kind: authorizationapi.UserKind,
					}},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}}, {
					ObjectMeta: metav1.ObjectMeta{
						Name:      "custom",
						Namespace: metav1.NamespaceDefault,
					},
					Subjects: []kapi.ObjectReference{
						{Name: "bar", Kind: authorizationapi.UserKind},
						{Name: "baz", Kind: authorizationapi.UserKind},
					},
					RoleRef: kapi.ObjectReference{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					}},
				},
			},
			existingRoles: &authorizationapi.RoleList{
				Items: []authorizationapi.Role{{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "edit",
						Namespace: metav1.NamespaceDefault,
					},
				}},
			},
		},
	}
	for tcName, tc := range tests {
		// Set up modifier options and run AddRole()
		o := &RoleModificationOptions{
			RoleName:            tc.inputRole,
			RoleBindingName:     tc.inputRoleBindingName,
			Users:               tc.inputSubjects,
			RoleNamespace:       metav1.NamespaceDefault,
			RoleBindingAccessor: NewLocalRoleBindingAccessor(metav1.NamespaceDefault, fakeauthorizationclient.NewSimpleClientset(tc.existingRoleBindings, tc.existingRoles).Authorization()),
		}

		modifyRoleAndCheck(t, o, tcName, tc.action, tc.expectedRoleBindingName, tc.expectedSubjects, tc.expectedWarning)
	}
}

func modifyRoleAndCheck(t *testing.T, o *RoleModificationOptions, tcName, action string, expectedName string, expectedSubjects []string, expectedWarning string) {
	var err error
	var warning string
	o.PrintErrf = func(format string, args ...interface{}) {
		warning = fmt.Sprintf(format, args...)
	}

	switch action {
	case "add":
		err = o.AddRole()
	case "remove":
		err = o.RemoveRole()
	default:
		err = fmt.Errorf("Invalid action %s", action)
	}
	if err != nil {
		t.Errorf("%s: unexpected err %v", tcName, err)
	}

	roleBinding, err := o.RoleBindingAccessor.GetRoleBinding(expectedName)
	if err != nil {
		t.Errorf("%s: err fetching roleBinding %s, %s", tcName, expectedName, err)
	}

	subjects, _ := authorizationapi.StringSubjectsFor(roleBinding.Namespace, roleBinding.Subjects)
	if !reflect.DeepEqual(expectedSubjects, subjects) {
		t.Errorf("%s: err expected users: %v, actual: %v", tcName, expectedSubjects, subjects)
	}
	if warning != expectedWarning {
		t.Errorf("%s: unexpected warning: expected: '%s', actual: '%s'", tcName, expectedWarning, warning)
	}

}
