from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.firefox import GeckoDriverManager

driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()))

def test_eight_components():

    driver.get("http://127.0.0.1:8080/../../../../../etc/passwd")

    driver.implicitly_wait(0.5)

    # title = driver.title
    # assert title == "Web form"

    # text_box = driver.find_element(by=By.NAME, value="my-text")
    # submit_button = driver.find_element(by=By.CSS_SELECTOR, value="button")

    # text_box.send_keys("Selenium")
    # submit_button.click()

    # message = driver.find_element(by=By.ID, value="message")
    # value = message.text
    # assert value == "Received!"

    driver.quit()

test_eight_components()