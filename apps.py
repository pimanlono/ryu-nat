import logging


class App(object):

    def __init__(self, *args, **kwargs):

        FORMAT = '%(asctime)-15s %(clientip)s %(user)-8s %(message)s'
        logging.basicConfig(format=FORMAT)
        self.logger = logging.getLogger('ryuapp_loger')
