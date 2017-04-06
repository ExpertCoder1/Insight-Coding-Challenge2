
Insight-data-engineering-coding-challenge

The coding challenge is solved using data structures in Java.

HashMap is used to store frequency visits, which contains all the information regarding all host access.
To count hours based traffic  I have used FIFO queue using linked list. 
Node class is used to maintain hourly base request.
Top 10 busiest hour or networking trafficing is solved using arrays.
The log_input file log.txt and log-output files - blocked.txt, hosts.txt, hours.txt and resources.txt are part of the program.

Feature 1:  Count frequency of visitor by hostname and response code:
Here, The Definition of feature1 hasn't specified about failed login, So I am couting failed login as active access by the host.
Parameter there are being passed : (hostname, response code)

Feature 2: Measure bandwidth that has been consumed by various resources of the website.

Feature 3 : Add nodes into Queue for measuring request per hour.

Feature 4 :Failed Login Attempts.
 LOGIC used for blocked IP addresses:
		 Test Case : Success - no log
		 Test Case : FAIL SUCCESS - no log
		 Test Case : FAIL FAIL SUCCESS - no log
		 Test Case : FAIL FAIL FAIL - log and blocked for five min and count all success and fail log.
