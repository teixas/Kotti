class TestSanitizer:

    def test_allowed_tags(self, root, db_session, events,
                          dummy_request, content):
        from kotti.resources import Document

        document = root['document'] = Document(body=u'<a>link</a>')
        db_session.flush()
        assert document.body == u'<a>link</a>'

    def test_disallowed_tags(self, root, db_session, events, dummy_request):
        from kotti.resources import Document

        document = root['document'] = Document(body=u'<iframe></iframe>')
        db_session.flush()
        assert document.body == u'&lt;iframe&gt;&lt;/iframe&gt;'
