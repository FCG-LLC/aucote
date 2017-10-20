import time

from api.handler import Handler


class StorageHandler(Handler):
    LIST_NAME = None
    LIST_URL = '/api/v1/{name}?limit={limit}&page={page}'

    @Handler.limit
    def get(self, rowid=None, limit=10, page=0):
        """
        Handle get method and returns aucote status in JSON

        Returns:
            None - writes aucote status in JSON

        """
        if not rowid:
            result = self.list(limit, page)
            result['navigation'] = {
                'limit': limit,
                'page': page,
                'next_page': self.url_list(limit, page + 1),
                'previous_page': self.url_list(limit, page - 1 if page > 0 else 0)
            }
        else:
            result = self.details(int(rowid))

        result['meta'] = {
            'timestamp': time.time()
        }
        self.write(result)

    def list(self, limit, page):
        raise NotImplementedError

    def details(self, rowid):
        raise NotImplementedError

    def url_list(self, limit, page):
        return self.format_url(self.LIST_URL.format(name=self.LIST_NAME, limit=limit, page=page))
