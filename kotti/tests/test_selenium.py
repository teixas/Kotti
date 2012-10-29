from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
import unittest


class Basic(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Firefox()
        self.driver.implicitly_wait(30)
        self.base_url = "http://localhost:5000"
        self.verificationErrors = []

    def test_basic(self):
        driver = self.driver
        driver.get(self.base_url + "/")
        self.assertEqual("Welcome to Kotti",
                         driver.find_element_by_css_selector("h1").text)

    def is_element_present(self, how, what):
        try:
            self.driver.find_element(by=how, value=what)
        except NoSuchElementException:
            return False
        return True

    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)

if __name__ == "__main__":
    unittest.main()
