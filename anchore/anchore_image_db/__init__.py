def load(driver=None, config={}):
    try:
        module = __import__("anchore.anchore_image_db", fromlist=[driver])
        c = getattr(module, driver)
    except:
        import traceback
        traceback.print_exc()
        raise Exception ("DB driver not found: " + str(driver))
    return(c.AnchoreImageDB(config=config))



#class ADB(object):
#    def __init__(self, driver=None, config={}):
#        self.driver = driver
#        self.config = config
#        try:
#            self.load()
#        except:
#            import traceback
#            traceback.print_exc()
#            raise Exception ("DB driver not found: " + str(self.driver))

#    def load(self):
#        module = __import__("anchore.anchore_image_db", fromlist=[self.driver])
#        c = getattr(module, self.driver)
#        return(c.AnchoreImageDB(config=self.config))
