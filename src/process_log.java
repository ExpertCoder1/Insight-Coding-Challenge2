/*
 * @author : Ulka
 */


/*
Imports
*/

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.File;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

class CONSTANT{
	public final static int TOP10 = 10;
	/*
	 * Regex for log parsing. host_name time_stamp request response_code bytes
	 */
	public static final String REGEX = "([\\w.,-]+) ([-]) ([-]) \\[([\\w:/]+\\s[+\\-]\\d{4})\\] \"((.*))\" (\\d+) ([(\\d),-]+)";
	/*
	 * DateFormat for parsing.
	 */
	public static final SimpleDateFormat parser = new SimpleDateFormat("dd/MMM/yyyy:HH:mm:ss");
	/*
	 * Feature 1 : hosts.txt
	 */
	public static final File hostsFile = new File("..\\log_output\\hosts.txt");
	/*
	 * Feature 2 : resources.txt
	 */
	public static final File resourceFile = new File("..\\log_output\\resources.txt");
	/*
	 * Feature 3 : hours.txt
	 */
	public static final File hoursFile = new File("..\\log_output\\hours.txt");
	/*
	 *  Feature 4 : blocked.txt
	 */
	public static final File blockFile = new File("..\\log_output\\blocked.txt");
	
	public static final long MIN = 1000*60;
} 

/*
 * EVERITHING STARTS FROM HERE.. :)
 * 
 */
public class process_log{
	
	/*
	 * frequencyVisit : Contains all the information regarding all host access.
	 */
	public static Map<String,Integer> frequencyVisit = new HashMap<String,Integer>();
	public static Map<String,Long> frequencyBandwidth = new HashMap<String,Long>();
	public static Map<String,HostInfo> hostInfo = new HashMap<String,HostInfo>();
	public static Node rear = null;
    public static Node front = null;
    public static Long nodecounter = 1l;
    
	public static void main(String[] args){
		/*
		 * Log file
		 */
		File log_file = new File("..\\log_input\\log.txt");
		run(log_file);
	}
	
	public static void run(File log_file){
		/*
		 * FOUR FEATURES ARE START MAINTAINING FROM HERE.
		 */
		BufferedReader br = null;
		BufferedWriter bw = null;
		String stamp_log = null;
		long start,end;
		Pattern pattern = null;
		Matcher matcher = null;
		TopTenVisitors topTenVisitor = null;
		TopTenResources topTenResource = null;
		TopTenTrafficHour topTenBussiestHours = null;
		
		try{
			
			br = new BufferedReader(new FileReader(log_file));
			bw = new BufferedWriter(new FileWriter(CONSTANT.blockFile));
			topTenVisitor = new TopTenVisitors();
			topTenResource = new TopTenResources();
			topTenBussiestHours = new TopTenTrafficHour();
			
			start = System.currentTimeMillis();
			pattern = Pattern.compile(CONSTANT.REGEX);
			while((stamp_log = br.readLine())!=null){
				matcher = pattern.matcher(stamp_log);
				if(matcher.find()){
					/* Feature 1 :
					 * Count frequency of visitor by hostname and response code : 
					 * Here, The Definition of feature1 hasn't specified about failed login, So I am couting failed login as active access by the host.
					 * Parameter there are being passed : (hostname, response code)
					 */
					countFrequencyOfVisitor(matcher.group(1),matcher.group(7),topTenVisitor);
					/* Feature 2 : 
					 * Measure bandwidth that has been consumed by various resources of the website.
					 * 
					 */
					countBandwidthConsumption(matcher.group(6),matcher.group(8),topTenResource);
					/* Feature 3 :
					 * Add nodes into Queue for measuring request per hour.
					 */
					countHourBasedTraffic(matcher.group(4),topTenBussiestHours);
					/* Feature 4 :
					 * Failed Login Attempts.
					 */
					countFailedLoginAttempts(matcher.group(1),matcher.group(4),matcher.group(7),matcher.group(0),bw);
					//printMatcher(matcher);
					
				}else{
					System.err.println("This log line isn't parsable. Please check your regex against Log Line : "+stamp_log);
				}
			}
			end = System.currentTimeMillis();
			System.out.println("Time taken : "+(end-start) + " Millis");
			/*
			 * Taking out at the end of the log file but you can take at realtime as well.
			 */
			topTenVisitor.print();
			topTenResource.print();
			topTenBussiestHours.print();
			
			br.close();
			bw.close();
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public static void countFailedLoginAttempts(String hostName, String timeStamp, String responceCode,String log, BufferedWriter bw){
		/*
		 *  LOGIC for blocked IP addresses.
		 *  Test Case : Success - no log
		 *  Test Case : FAIL SUCCESS - no log
		 *  Test Case : FAIL FAIL SUCCESS - no log
		 *  Test Case : FAIL FAIL FAIL - log and blocked for five min and count all success and fail log.
		 */
		HostInfo host = null;
		try{
			Date currTime = CONSTANT.parser.parse(timeStamp);
			if(responceCode!=null){
				if(hostInfo.containsKey(hostName)){
					host = hostInfo.get(hostName);
					
					if(host.getIsDiable() && (host.getDisableAccess().getTime()-currTime.getTime())>=0l){
						bw.write(log);
						bw.newLine();
					}else if("302".equals(responceCode)){
						if(host.getIsTwenty() && (host.getTwentyTimer().getTime()-currTime.getTime())>=0l){
							host.setFailedCount((host.getFailedCount())+1);
							if(host.getFailedCount()==3){
								host.setIsDiable(true); host.setDisableAccess(new Date(currTime.getTime()+(5*CONSTANT.MIN)));
								bw.write(log);
								bw.newLine();
							}
						}else{
							host.setFailedCount(1); 
							host.setTwentyTimer(new Date(currTime.getTime()+20000));host.setIsTwenty(true);
							host.setIsDiable(false);
						}
					}else{
						hostInfo.remove(hostName);
					}
				}else if("302".equals(responceCode)){
					/*
					 * First Time Failed Login host.
					 */
					host = new HostInfo();
					host.setIP(hostName); host.setFailedCount(1); 
					host.setTwentyTimer(new Date(currTime.getTime()+20000));host.setIsTwenty(true);
					host.setIsDiable(false);host.setDisableAccess(null);
					
					hostInfo.put(hostName,host);
				}
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		
	}
	public static void countHourBasedTraffic(String timestamp,TopTenTrafficHour topTenBussiestHours){
		/*
		 * User FIFO queue using LINKED LIST
		 */
		
		Node current = null;
		if(timestamp!=null && !timestamp.trim().isEmpty()){
			current = createNode(timestamp);
			if(rear == null){
				// First node of the Queue link list.
				current.setNext(null);
				rear = current;
				front = current;
			}else{
				if(difference(rear.getDate(), current.getDate()) > 0){
					/* remove rear node and make it count.
					*  take required info : datetime count
					*/
					while(difference(rear.getDate(), current.getDate()) > 0){
						//System.out.println("DateTime : "+rear.getDate()+" : Count : "+((front.getCount().longValue()-rear.getCount().longValue())+1));
						countHoursTrafficing(rear.getDate(),((front.getCount().longValue()-rear.getCount().longValue())+1),timestamp,topTenBussiestHours);
						/*
						 * remove rear node and make next node as rear.
						 */
						rear = rear.getNext();
					}
					/* 
					 * put current node at front.
					 */
					front.setNext(current);
					front = current;
				}else{
					/* 
					 * put current node at front.
					 */
						front.setNext(current);
						front = current;
				}
			}
		}
	}
	public static void countHoursTrafficing(Date date,Long count,String timeStamp,TopTenTrafficHour topTenBussiestHours){
		BussiestHour bussyHour = null;
		if(topTenBussiestHours.getHoursTraffics().size() < CONSTANT.TOP10){
			bussyHour = new BussiestHour();
			bussyHour.setDate(date); bussyHour.setCount(count); bussyHour.setTimeStamp(timeStamp);
			topTenBussiestHours.addTrafficHour(bussyHour);
		}else if(topTenBussiestHours.lastCount().getCount().compareTo(count) < 0){
			bussyHour = new BussiestHour();
			bussyHour.setDate(date); bussyHour.setCount(count);bussyHour.setTimeStamp(timeStamp);
			topTenBussiestHours.addTrafficHour(bussyHour);
		}
	}
	
	public static long difference(Date from,Date to){
		return (to.getTime() - from.getTime())/(60*60*1000);
	}
	
	public static Node createNode(String timestamp){
		Node tmp = null;
		try{
			tmp = new Node();
			tmp.setDate(CONSTANT.parser.parse(timestamp));
			tmp.setCount(nodecounter);
			nodecounter++;
		}catch(Exception e){
			e.printStackTrace();
		}
		return tmp;
	}
	public static void countBandwidthConsumption(String request_response, String b,TopTenResources topTenResources){
		Resource resource = null;
		Long tmp = 0l;
		String resourceName = getResource(request_response);
		Long bytes = getBytes(b);
		if(resourceName != null && !resourceName.isEmpty() && bytes > 0l){
			if(frequencyBandwidth.containsKey(resourceName)){
				tmp = frequencyBandwidth.get(resourceName)+bytes;
				frequencyBandwidth.put(resourceName, tmp);
			}else{
				frequencyBandwidth.put(resourceName, bytes);
			}
			
			if(topTenResources.getResources().size() < CONSTANT.TOP10){
				resource = new Resource();
				resource.setName(resourceName); resource.setBytes(frequencyBandwidth.get(resourceName));
				topTenResources.addResource(resource);
			}else if(topTenResources.lastCount().getBytes().compareTo(frequencyBandwidth.get(resourceName)) < 0){
				resource = new Resource();
				resource.setName(resourceName); resource.setBytes(frequencyBandwidth.get(resourceName));
				topTenResources.addResource(resource);
			}
		}
		if(resourceName == null){
			//.err.println("Invalid Resource URL : "+request_response);
		}
	}
	
	public static Long getBytes(String bytes){
		Long res_bytes = 0l;
		try{
			if(bytes != null && !bytes.trim().isEmpty() && !bytes.trim().trim().equals("-")){
				res_bytes = Long.parseLong(bytes);
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		return res_bytes;
	}
	
	public static String getResource(String request_response){
		String resource = null;
		String [] spliter = null;
		if(request_response != null && !request_response.trim().isEmpty()){
			spliter = request_response.split(" ");
			if(spliter.length >= 2){
				resource = spliter[1];
			}else if(spliter.length == 1){
				resource = spliter[0];
			}
		}
		return resource;
	}
	public static void countFrequencyOfVisitor(String hostName, String responseCode,TopTenVisitors topTenVisitor){
		/*
		 * 
		 * 401 is failed login. If we have more than one failed login response code than have to be careful for rest of all fail code.
		 * If you want only active user login without any failed attempt than you have to take a good care of response code.
		 * As per the definition, I have calculated all the request that has made by each host.
		 * 
		 */
		Visitor visitor = null;
		int tmp = 0;
		if(responseCode != null && !responseCode.isEmpty()){
			if(frequencyVisit.containsKey(hostName)){
				tmp = frequencyVisit.get(hostName)+1;
				frequencyVisit.put(hostName, tmp);
			}else{
				frequencyVisit.put(hostName, 1);
			}
			
			if(topTenVisitor.getVisitors().size() < CONSTANT.TOP10){
				visitor = new Visitor();
				visitor.setHostName(hostName); visitor.setCount(frequencyVisit.get(hostName));
				topTenVisitor.addVisiter(visitor);
			}else if(topTenVisitor.lastCount().getCount() < frequencyVisit.get(hostName)){
				visitor = new Visitor();
				visitor.setHostName(hostName); visitor.setCount(frequencyVisit.get(hostName));
				topTenVisitor.addVisiter(visitor);
			}
			
		}
	}
	
	/*
	 * Print parsed Log.
	 */
	public static void printMatcher(Matcher matcher){
		System.out.println("hostname : "+matcher.group(1));
		System.out.println("time stamp : "+matcher.group(4));
		System.out.println("request_resource: "+matcher.group(6));
		System.out.println("responsecode : "+matcher.group(7));
		System.out.println("bytes : "+matcher.group(8));
	}
}
/*
 * Host Info class to maintain host info.
 */
class HostInfo{
	private String IP;
	private int failedCount;
	private Date twentyTimer;
	private Boolean isTwenty;
	private Date DisableAccess;
	private Boolean isDiable;
	public String getIP() {
		return IP;
	}
	public void setIP(String iP) {
		IP = iP;
	}
	public int getFailedCount() {
		return failedCount;
	}
	public void setFailedCount(int failedCount) {
		this.failedCount = failedCount;
	}
	public Date getTwentyTimer() {
		return twentyTimer;
	}
	public void setTwentyTimer(Date twentyTimer) {
		this.twentyTimer = twentyTimer;
	}
	public Boolean getIsTwenty() {
		return isTwenty;
	}
	public void setIsTwenty(Boolean isTwenty) {
		this.isTwenty = isTwenty;
	}
	public Date getDisableAccess() {
		return DisableAccess;
	}
	public void setDisableAccess(Date disableAccess) {
		DisableAccess = disableAccess;
	}
	public Boolean getIsDiable() {
		return isDiable;
	}
	public void setIsDiable(Boolean isDiable) {
		this.isDiable = isDiable;
	}
}
/*
 *  Node class : Is used to maintain hourly base request.
 */
class Node{
	private Date date;
	private Long count;
	private Node next;
	public Date getDate() {
		return date;
	}
	public void setDate(Date date) {
		this.date = date;
	}
	public Long getCount() {
		return count;
	}
	public void setCount(Long count) {
		this.count = count;
	}
	public Node getNext() {
		return next;
	}
	public void setNext(Node next) {
		this.next = next;
	}
}
/*
 * Top10Bussiest hour | newtwork trafficing.
 */
class TopTenTrafficHour implements Comparator<BussiestHour>{
	private List<BussiestHour> hoursTraffics;
	public TopTenTrafficHour(){
		hoursTraffics = new ArrayList<BussiestHour>();
	}
	public List<BussiestHour> getHoursTraffics() {
		return hoursTraffics;
	}
	public void addTrafficHour(BussiestHour b){
		if(contains(b)){
			// No add operation required.
		}else if(hoursTraffics.size() < 10){
			hoursTraffics.add(b);
		}else{
			hoursTraffics.remove(0);
			hoursTraffics.add(b);
		}
		Collections.sort(hoursTraffics,new TopTenTrafficHour());
	}
	/*
	 * Print top 10 active host in descending order that were using NASA web resources.
	 */
	public void print(){
		Collections.reverse(hoursTraffics);
		BufferedWriter bw = null;
		
		try{
			bw = new BufferedWriter(new FileWriter(CONSTANT.hoursFile));
			
			for(BussiestHour b : hoursTraffics){
				bw.write(b.getTimeStamp()+","+b.getCount());
				bw.newLine();
			}
			bw.close();
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	public BussiestHour lastCount(){
		if(!hoursTraffics.isEmpty()){
			return hoursTraffics.get(0);
		}else{
			return null;
		}
	}
	@Override
	public int compare(BussiestHour o1, BussiestHour o2) {
		return o1.getCount().compareTo(o2.getCount());
	}
	public boolean contains(BussiestHour b){
		boolean rr = false;
		for(BussiestHour comBus : hoursTraffics){
			if(comBus.equals(b) && Long.compare(comBus.getCount(), b.getCount())>0){
				comBus.setCount(comBus.getCount());
				rr = true;
				break;
			}
		}
		return rr;
	}
}
class BussiestHour{
	private Date date;
	private Long count;
	private String timeStamp;
	public Date getDate() {
		return date;
	}
	public void setDate(Date date) {
		this.date = date;
	}
	public Long getCount() {
		return count;
	}
	public void setCount(Long count) {
		this.count = count;
	}
	
	public String getTimeStamp() {
		return timeStamp;
	}
	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}
	public boolean equals(BussiestHour b){
		return this.timeStamp.equals(b.getTimeStamp());
	}
}
/*
 * Top10visitors contains top 10 host that has been actively using NASA's fan page. 
 */
class TopTenVisitors implements Comparator<Visitor>{
	
	private List<Visitor> visitors;
	public TopTenVisitors(){
		visitors = new ArrayList<Visitor>();
	}
	public List<Visitor> getVisitors(){
		return visitors;
	}
	public void addVisiter(Visitor v){
		if(contains(v)){
			/*
			 * Same host made entry in top 10 again : Update only count not object. 
			 */
		}else if(visitors.size() < 10){
			visitors.add(v);
		}else{
			visitors.remove(0);
			visitors.add(v);
		}
		Collections.sort(visitors,new TopTenVisitors());
	}
	public Visitor lastCount(){
		if(!visitors.isEmpty()){
			return visitors.get(0);
		}else{
			return null;
		}
	}
	/*
	 * Print top 10 active host in descending order that were using NASA web resources.
	 */
	public void print(){
		Collections.reverse(visitors);
		BufferedWriter bw = null;
		
		try{
			bw = new BufferedWriter(new FileWriter(CONSTANT.hostsFile));
			
			for(Visitor v : visitors){
				bw.write(v.getHostName()+","+v.getCount());
				bw.newLine();
			}
			bw.close();
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public boolean contains(Visitor v){
		boolean rr = false;
		for(Visitor comVis : visitors){
			if(comVis.equals(v) && Integer.compare(comVis.getCount(), v.getCount())<0){
				comVis.setCount(v.getCount());
				rr = true;
				break;
			}
		}
		return rr;
	}
	@Override
    public int compare(Visitor o1, Visitor o2) {
        return o1.getCount().compareTo(o2.getCount());
    }
}

class Visitor{
	private String hostName;
	private Integer count;
	public String getHostName() {
		return hostName;
	}
	public void setHostName(String hostName) {
		this.hostName = hostName;
	}
	public Integer getCount() {
		return count;
	}
	public void setCount(Integer count) {
		this.count = count;
	}
	public boolean equals(Visitor v){
		return this.getHostName().equalsIgnoreCase(v.getHostName());
	}
}

class TopTenResources  implements Comparator<Resource>{
	private List<Resource> resources;
	public TopTenResources(){
		resources = new ArrayList<Resource>();
	}
	public List<Resource> getResources(){
		return resources;
	}
	public void addResource(Resource r){
		if(contains(r)){
			/*
			 * Same host made entry in top 10 again : Update only count not object. 
			 */
		}else if(resources.size() < 10){
			resources.add(r);
		}else{
			resources.remove(0);
			resources.add(r);
		}
		Collections.sort(resources,new TopTenResources());
	}
	public Resource lastCount(){
		if(!resources.isEmpty()){
			return resources.get(0);
		}else{
			return null;
		}
	}
	/*
	 * Print top 10 highest bandwidth consuming resouces.
	 */
	public void print(){
		Collections.reverse(resources);
		BufferedWriter bw = null;
		
		try{
			bw = new BufferedWriter(new FileWriter(CONSTANT.resourceFile));
			
			
			for(Resource r : resources){
				bw.write(r.getName());
				bw.newLine();
			}
			
			bw.close();
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	public boolean contains(Resource r){
		boolean rr = false;
		for(Resource comRes : resources){
			if(comRes.equals(r) && Long.compare(comRes.getBytes(), r.getBytes())<0){
				comRes.setBytes(r.getBytes());
				rr = true;
				break;
			}
		}
		return rr;
	}
	@Override
	public int compare(Resource o1, Resource o2) {
		return o1.getBytes().compareTo(o2.getBytes());
	}
}

class Resource{
	private String name;
	private Long bytes;
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public Long getBytes() {
		return bytes;
	}
	public void setBytes(Long bytes) {
		this.bytes = bytes;
	}
	public boolean equals(Resource v){
		return this.getName().equalsIgnoreCase(v.getName());
	}
}
