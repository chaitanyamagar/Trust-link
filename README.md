# Trust-link
Phishing is a critical cybersecurity threat, involving fraudulent attempts to steal sensitive information such as login credentials, credit card details, and more. TrustLink aims to provide an accessible, efficient, and user-friendly solution to detect and classify URLs as safe, suspicious, or malicious based on predefined parameters.  
This project integrates Python for backend logic, HTML/CSS/JavaScript for the user interface, and TailwindCSS for styling. It demonstrates how modern technology can help protect users from potential online threats.

2. Technology Stack
Frontend
HTML: Provides the structure of the web page.
CSS (TailwindCSS): Enhances the design with responsive and modern styling.
JavaScript: Handles dynamic interactions between the user and the backend.
Backend
Python: Implements the core phishing detection logic.
Flask: A lightweight Python web framework to handle routing and API creation.
External Libraries
Font Awesome: For icons used in the user interface.
Regular Expressions (re): For URL pattern matching.
VirusTotal API: Optional integration for additional threat detection.
3. Advantages
Strengths
User-Friendly Interface:
Designed with simplicity and accessibility in mind.
Efficient URL Analysis:
Performs keyword checks, URL structure analysis, and VirusTotal integration.
Cross-Platform Compatibility:
The app works seamlessly on mobile and desktop devices.
Scalable Backend:
Flask's lightweight nature allows easy deployment and scaling.
Real-Time Detection:
Provides immediate feedback to users on potential threats.
Weaknesses
API Dependency:
Requires VirusTotal API for advanced checks, which may incur costs for large-scale usage.
Static Analysis:
Cannot detect phishing threats beyond the URL (e.g., suspicious page content).
False Positives/Negatives:
Some URLs may be flagged incorrectly based on predefined heuristics.
![TrustLinkige](https://github.com/user-attachments/assets/032ef685-802d-4546-97be-0fd8b55578e1)
