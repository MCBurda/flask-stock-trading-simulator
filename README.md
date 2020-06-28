# Flask Stock Trading Simulator

This is a Stock Trading simulator that I built for the Harvard CS50 class.

The simulator is built as a web application that runs on Flask and uses the API of the IEX exchange (https://iexcloud.io/) to pull data on stocks from the web. 
Based on the URL Routes that the user visits, I am rendering out different HTML content and making GET requests to the IEX API to display data. The app allows the user to quote, buy, and sell stocks. Additionally, the user can view his portfolio holdings in a dashboard and see an overview of all his past transactions. The app is hooked up to an SQLite database with two tables: users and transactions.
