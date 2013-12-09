package tordns.localproxy;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;


public class DNSServer extends Thread {

	public Config Config = new Config();

	public boolean running=true;
	public DatagramSocket serverSocket = null;
	public DatagramSocket clientSocket=null;
	
	private OnionRouter Router = null;
	
	public void run() {
		while (running) try { ServerDNS(); } catch(Exception E) { Config.EXC(E,"Server"); }
		try { serverSocket.close(); } catch(Exception E) {}
	}
	
	DNSServer(Config C,OnionRouter R) throws Exception {
		super();
		Config = C;
		Router = R;
		running=false;
		serverSocket = new DatagramSocket(53); 
		
		running=true;
		start();
	}
	
private void ServerDNS() throws Exception {

		 while(running)
               {
                  byte[] receiveData = new byte[512];
			 	  DatagramPacket receivePacket = new DatagramPacket(receiveData, 512);
                  serverSocket.receive(receivePacket);
                  InetAddress sourceAddr = receivePacket.getAddress();
                  int sourcePort = receivePacket.getPort();
                  int size = receivePacket.getLength();
                  DNSPacket D = new DNSPacket(receivePacket);
                //0 if (D.response) continue; //Rispondo io non tu!
                  if (D.response==true) continue;
                  if (Config.DNSLogQuery) Config.Log("DNS: Req "+D.id+"\t"+D.qtype+"\t"+(D.response ? "A" : "Q")+"\t"+Integer.toHexString(D.rawhead)+"\tF: "+sourceAddr.toString()+":"+sourcePort+"\tH: `"+ D.Host+"`\n");
                  
                  if (!FireWallizer.IPCan(Config, sourceAddr)) {
                	Config.Log("FireWallizer: "+sourceAddr.toString()+" Drop!\n");
                	continue;
                  	}
                  
                  if (Config.DNSTorify || D.Tld.compareTo("onion")==0) {
                	  //DNS onion
               
                	  D = Router.QueryDNS(D);
                      byte[]  sendData = D.DoReply();
                 	  DatagramPacket sendPacket =  new DatagramPacket(sendData, sendData.length, sourceAddr, sourcePort);
                 	  serverSocket.send(sendPacket);
                  } else {
                	  //DNS Proxy "Normale"
                	 clientSocket = new DatagramSocket();
                	 clientSocket.setSoTimeout(Config.DNSSoTimeout);
                	 try {                		 
	                	 DatagramPacket sendPacket =  new DatagramPacket(receivePacket.getData(), size,Config.DNSServer,53);
	                	 clientSocket.send(sendPacket);
	                	 receiveData = new byte[512];
	                	 receivePacket = new DatagramPacket(receiveData, 512);
	                	 clientSocket.receive(receivePacket);
	                	 if (Config.DNSLogQuery) Config.Log("DNS: Reply by DNSServer\n");
	                	 DatagramPacket replyPacket =  new DatagramPacket(receivePacket.getData(), receivePacket.getLength(), sourceAddr,sourcePort);
	                	 serverSocket.send(replyPacket);
                	 	} catch(SocketTimeoutException T) { Config.Log("DNS: "+Config.DNSServer.toString()+" Timeout\n");} 
                  	}
               }
	}
}
