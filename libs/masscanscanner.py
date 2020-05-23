import masscan
# First remove python-masscan if installed: pip uninstall python-masscan
# Then install the no-log fork with: pip install python-masscan-nolog

portList = [554, 555, 5544, 5554, 8554, 1554] # Other commong RTSP ports: 555, 8554, 1554, 7070, 1935, 10554
targetList = dict()

def detect(iprange):
    try:
        converted_list = [str(element) for element in portList]
        ports = ','.join(converted_list)
        mas = masscan.PortScanner()
        mas.scan(iprange, ports=ports, arguments='--max-rate 100000')
        return mas.scan_result["scan"]
    except:
        return None