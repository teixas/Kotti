from webob.multidict import MultiDict
from pytest import raises
from pyramid.exceptions import Forbidden


class TestAddableTypes:
    def test_view_permitted_yes(self, config, db_session, dummy_request):
        from kotti.resources import Node
        from kotti.resources import Document

        config.testing_securitypolicy(permissive=True)
        config.include('kotti.views.edit.content')
        root = db_session.query(Node).get(1)
        assert Document.type_info.addable(root, dummy_request) is True

    def test_view_permitted_no(self, config, db_session, dummy_request):
        from kotti.resources import Node
        from kotti.resources import Document

        config.testing_securitypolicy(permissive=False)
        config.include('kotti.views.edit.content')
        root = db_session.query(Node).get(1)
        assert Document.type_info.addable(root, dummy_request) is False


class TestNodePaste:
    def test_get_non_existing_paste_item(self, db_session, dummy_request):
        from kotti.resources import Node
        from kotti.views.edit import get_paste_items

        root = db_session.query(Node).get(1)
        dummy_request.session['kotti.paste'] = ([1701], 'copy')
        item = get_paste_items(root, dummy_request)
        assert item == []

    def test_paste_non_existing_node(self, db_session, dummy_request):
        from kotti.resources import Node
        from kotti.views.edit.actions import NodeActions

        root = db_session.query(Node).get(1)

        for index, action in enumerate(['copy', 'cut']):
            dummy_request.session['kotti.paste'] = ([1701], 'copy')
            response = NodeActions(root, dummy_request).paste_nodes()
            assert response.status == '302 Found'
            assert len(dummy_request.session['_f_error']) == index + 1

    def test_paste_without_edit_permission(
        self, config, db_session, dummy_request):
        from kotti.resources import Node
        from kotti.views.edit.actions import NodeActions

        root = db_session.query(Node).get(1)
        dummy_request.params['paste'] = u'on'
        config.testing_securitypolicy(permissive=False)

        # We need to have the 'edit' permission on the original object
        # to be able to cut and paste:
        dummy_request.session['kotti.paste'] = ([1], 'cut')
        view = NodeActions(root, dummy_request)
        with raises(Forbidden):
            view.paste_nodes()

        # We don't need 'edit' permission if we're just copying:
        dummy_request.session['kotti.paste'] = ([1], 'copy')
        response = NodeActions(root, dummy_request).paste_nodes()
        assert response.status == '302 Found'


class TestNodeRename:
    def test_rename_to_empty_name(self, db_session, dummy_request):
        from kotti.resources import Node
        from kotti.resources import Document
        from kotti.views.edit.actions import NodeActions

        root = db_session.query(Node).get(1)
        child = root['child'] = Document(title=u"Child")
        dummy_request.params['rename'] = u'on'
        dummy_request.params['name'] = u''
        dummy_request.params['title'] = u'foo'
        NodeActions(child, dummy_request).rename_node()
        assert (dummy_request.session.pop_flash('error') ==
            [u'Name and title are required.'])

    def test_multi_rename(self, db_session, dummy_request):
        from kotti.resources import Node
        from kotti.resources import Document
        from kotti.views.edit.actions import NodeActions

        root = db_session.query(Node).get(1)
        root['child1'] = Document(title=u"Child 1")
        root['child2'] = Document(title=u"Child 2")
        dummy_request.POST = MultiDict()
        id1 = str(root['child1'].id)
        id2 = str(root['child2'].id)
        dummy_request.POST.add('children-to-rename', id1)
        dummy_request.POST.add('children-to-rename', id2)
        dummy_request.POST.add(id1 + '-name', u'')
        dummy_request.POST.add(id1 + '-title', u'Unhappy Child')
        dummy_request.POST.add(id2 + '-name', u'happy-child')
        dummy_request.POST.add(id2 + '-title', u'')
        dummy_request.POST.add('rename_nodes', u'rename_nodes')
        NodeActions(root, dummy_request).rename_nodes()
        assert dummy_request.session.pop_flash('error') ==\
            [u'Name and title are required.']

        dummy_request.POST.add(id1 + '-name', u'unhappy-child')
        dummy_request.POST.add(id1 + '-title', u'Unhappy Child')
        dummy_request.POST.add(id2 + '-name', u'happy-child')
        dummy_request.POST.add(id2 + '-title', u'Happy Child')
        dummy_request.POST.add('rename_nodes', u'rename_nodes')
        NodeActions(root, dummy_request).rename_nodes()
        assert dummy_request.session.pop_flash('success') ==\
            [u'Your changes have been saved.']


class TestNodeDelete:

    def test_multi_delete(self, db_session, dummy_request):
        from kotti.resources import Node
        from kotti.resources import Document
        from kotti.views.edit.actions import NodeActions

        root = db_session.query(Node).get(1)
        root['child1'] = Document(title=u"Child 1")
        root['child2'] = Document(title=u"Child 2")

        dummy_request.POST = MultiDict()
        id1 = str(root['child1'].id)
        id2 = str(root['child2'].id)
        dummy_request.POST.add('delete_nodes', u'delete_nodes')
        NodeActions(root, dummy_request).delete_nodes()
        assert dummy_request.session.pop_flash('info') ==\
            [u'Nothing deleted.']

        dummy_request.POST.add('children-to-delete', id1)
        dummy_request.POST.add('children-to-delete', id2)
        NodeActions(root, dummy_request).delete_nodes()
        assert dummy_request.session.pop_flash('success') ==\
            [u'${title} deleted.', u'${title} deleted.']


class TestNodeShare:
    def test_roles(self, db_session, dummy_request):
        from kotti.views.users import share_node
        from kotti.resources import get_root
        from kotti.security import SHARING_ROLES

        # The 'share_node' view will return a list of available roles
        # as defined in 'kotti.security.SHARING_ROLES'
        root = get_root()
        assert (
            [r.name for r in share_node(root, dummy_request)['available_roles']] ==
            SHARING_ROLES)

    def test_search(self, dummy_request, extra_principals):

        from kotti.resources import get_root
        from kotti.security import get_principals
        from kotti.security import set_groups
        from kotti.views.users import share_node

        root = get_root()
        P = get_principals()
        # Search for "Bob", which will return both the user and the
        # group, both of which have no roles:
        dummy_request.params['search'] = u''
        dummy_request.params['query'] = u'Bob'
        entries = share_node(root, dummy_request)['entries']
        assert len(entries) == 2
        assert entries[0][0] == P['bob']
        assert entries[0][1] == ([], [])
        assert entries[1][0] == P['group:bobsgroup']
        assert entries[1][1] == ([], [])

        # We make Bob an Editor in this context, and Bob's Group
        # becomes global Admin:
        set_groups(u'bob', root, [u'role:editor'])
        P[u'group:bobsgroup'].groups = [u'role:admin']
        entries = share_node(root, dummy_request)['entries']
        assert len(entries) == 2
        assert entries[0][0] == P['bob']
        assert entries[0][1] == ([u'role:editor'], [])
        assert entries[1][0] == P['group:bobsgroup']
        assert entries[1][1] == ([u'role:admin'], [u'role:admin'])

        # A search that doesn't return any items will still include
        # entries with existing local roles:
        dummy_request.params['query'] = u'Weeee'
        entries = share_node(root, dummy_request)['entries']
        assert len(entries) == 1
        assert entries[0][0] == P[u'bob']
        assert entries[0][1] == ([u'role:editor'], [])
        assert (dummy_request.session.pop_flash('info') ==
            [u'No users or groups found.'])

        # It does not, however, include entries that have local group
        # assignments only:
        set_groups(u'frank', root, [u'group:franksgroup'])
        dummy_request.params['query'] = u'Weeee'
        entries = share_node(root, dummy_request)['entries']
        assert len(entries) == 1
        assert entries[0][0] == P['bob']

    def test_apply(self, dummy_request, extra_principals):
        from kotti.resources import get_root
        from kotti.security import list_groups
        from kotti.security import set_groups
        from kotti.views.users import share_node

        root = get_root()

        dummy_request.params['apply'] = u''
        share_node(root, dummy_request)
        assert (dummy_request.session.pop_flash('info') ==
                [u'No changes made.'])
        assert list_groups('bob', root) == []
        set_groups('bob', root, ['role:special'])

        dummy_request.params['role::bob::role:owner'] = u'1'
        dummy_request.params['role::bob::role:editor'] = u'1'
        dummy_request.params['orig-role::bob::role:owner'] = u''
        dummy_request.params['orig-role::bob::role:editor'] = u''

        share_node(root, dummy_request)
        assert (dummy_request.session.pop_flash('success') ==
            [u'Your changes have been saved.'])
        assert (
            set(list_groups('bob', root)) ==
            set(['role:owner', 'role:editor', 'role:special'])
            )

        # We cannot set a role that's not displayed, even if we forged
        # the request:
        dummy_request.params['role::bob::role:admin'] = u'1'
        dummy_request.params['orig-role::bob::role:admin'] = u''
        with raises(Forbidden):
            share_node(root, dummy_request)
        assert (
            set(list_groups('bob', root)) ==
            set(['role:owner', 'role:editor', 'role:special'])
            )
