# -*- coding: utf-8 -*-
import warnings

from pyramid.httpexceptions import HTTPFound

from kotti.interfaces import IContent
from kotti.resources import get_root
from kotti.views.edit.default_views import DefaultViewSelection


class TestDefaultViewSelection:

    def test__is_valid_view(self, config, dummy_request):

        config.add_view(
            context=IContent,
            name='folder_view',
            permission='view',
            renderer='kotti:templates/view/folder.pt',
        )

        context = get_root()

        view = DefaultViewSelection(context, dummy_request)

        assert view._is_valid_view("folder_view") is True
        assert view._is_valid_view("foo") is False

    def test_default_views(self, config, dummy_request):
        config.add_view(
            context=IContent,
            name='folder_view',
            permission='view',
            renderer='kotti:templates/view/folder.pt',
            )

        context = get_root()

        view = DefaultViewSelection(context, dummy_request)

        sviews = view.default_view_selector()

        assert 'selectable_default_views' in sviews

        # the root should have at least the default view and the folder_view
        assert len(sviews['selectable_default_views']) > 1

        # the first view is always the default view
        assert sviews['selectable_default_views'][0]['is_current'] is True
        assert sviews['selectable_default_views'][0]['name'] == 'default'
        assert sviews['selectable_default_views'][0]['title'] == 'Default view'

        assert sviews['selectable_default_views'][1]['is_current'] is False

        # set the default view to folder_view view
        dummy_request.GET = {'view_name': 'folder_view'}
        view = DefaultViewSelection(context, dummy_request)

        assert type(view.set_default_view()) == HTTPFound
        assert context.default_view == 'folder_view'

        # set back to default
        dummy_request.GET = {'view_name': 'default'}
        view = DefaultViewSelection(context, dummy_request)

        assert type(view.set_default_view()) == HTTPFound
        assert context.default_view is None

        # try to set non existing view
        dummy_request.GET = {'view_name': 'nonexisting'}
        view = DefaultViewSelection(context, dummy_request)

        assert type(view.set_default_view()) == HTTPFound
        assert context.default_view is None

    def test_warning_for_non_registered_views(self, dummy_request):

        with warnings.catch_warnings(record=True) as w:

            DefaultViewSelection(
                get_root(), dummy_request).default_view_selector()

            assert len(w) == 1
            assert issubclass(w[-1].category, UserWarning)
            assert str(w[-1].message) == \
                "No view called 'folder_view' is registered for <Document 1 at />"
