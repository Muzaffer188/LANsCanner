
<a name="readme-top"></a>  

# SKY-SEC LAN Scanner  
#### by SKY-SEC Cyber Security Team  

[![ForTheBadge made-with-c](http://ForTheBadge.com/images/badges/made-with-c.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![ForTheBadge built-with-love](http://ForTheBadge.com/images/badges/built-with-love.svg)](https://github.com/Muzaffer188/)  
[![ForTheBadge built-by-developers](http://ForTheBadge.com/images/badges/built-by-developers.svg)](https://github.com/m3rtuc/)

<details>  
  <summary>Table of Contents</summary>  
  <ol>  
    <li>  
      <a href="#about-the-project">About The Project</a>  
      <ul>  
        <li><a href="#what-is-the-purpose">What Is The Purpose?</a></li>  
      </ul>  
    </li>  
    <li>  
      <a href="#usage">Usage</a>  
      <ul>  
        <li><a href="#how-can-i-run-this-tool">How Can I Run This Tool?</a></li>  
      </ul>  
      <ul>  
        <li><a href="#examples-with-photos">Examples with Photos</a></li>  
      </ul>  
    </li>   
    <li><a href="#references">References</a></li>
    <li><a href="#contact">Contact</a></li>  
    <li><a href="#to-know-more-about-us">To Know More About Us</a></li>      
  </ol>  
</details>  

## About The Project  

SKY-SEC LAN Scanner is a lightweight and efficient tool designed in C language to identify the IP (Internet Protocol) address and MAC (Media Access Control) addresses of active devices on a network using ARP (Address Resolution Protocol). This project has been developed to provide insights into how ARP-based network tools work while providing a user-friendly interface for network scanning.  

<p align="right">(<a href="#readme-top">back to top</a>)</p>  

### What is the purpose?  

This tool serves as:  
- A practical example of how ARP-based tools operate under the hood.  
- A network analysis tool for discovering active IP addresses and their associated MAC addresses in a given range.  
- A way to facilitate learning and experimentation with low-level network programming in C.  

## Usage  

### How can I run this tool?  

#### Prerequisites:  
- Linux system (the tool uses Linux-specific APIs).  
- Root privileges (required for raw socket operations).  
- C compiler (e.g., gcc).  

#### Steps:  

1. Clone the repository:  
   ```bash
   git clone https://github.com/skylab-kulubu/LANsCanner.git  
   cd LANsCanner  
   ```

2. Compile the source code:  
   ```bash
   gcc -o LAN_Scanner LANsCanner.c  
   ```

3. Run the tool with the required parameters:  
   ```bash
   sudo ./LAN_Scanner <INTERFACE> <START_IP> <END_IP>  
   ```

   **Parameters:**  
   - `<INTERFACE>`: The network interface to use (e.g., eth0, wlan0).  
   - `<START_IP>`: Starting IP address for the scan (e.g., 192.168.1.1).
   - `<END_IP>`: Ending IP address for the scan (e.g., 192.168.1.255).  

   **Example:**  
   ```bash
   sudo ./Lan_Scanner wlan0 192.168.1.1 192.168.1.10  
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>  

### Examples with Photos  

#### ![tool_running](https://github.com/skylab-kulubu/LANsCanner/blob/main/SKY-SEC_LAN_Scanner1.jpg)  
The scanner outputs active IP addresses and their corresponding MAC addresses in real time.  

<p align="right">(<a href="#readme-top">back to top</a>)</p>  

## References  
  
[ARP Request and Reply Using C Socket Programming](https://stackoverflow.com/questions/16710040/arp-request-and-reply-using-c-socket-programming)  

<p align="right">(<a href="#readme-top">back to top</a>)</p>  

## Contact  

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Muzaffer188/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/muzaffer-emer/) 

[![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/m3rtuc/)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/mert-%C3%BC%C3%A7-6b20b82aa/) 

<p align="right">(<a href="#readme-top">back to top</a>)</p>  

## To Know More About Our Student Branch  
### [SKY LAB : Yıldız Technical University Computer Science Club](http://yildizskylab.com/ "SKY LAB Homepage")
