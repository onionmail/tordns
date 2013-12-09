package tordns.localproxy;
import java.io.FileOutputStream;
import java.lang.management.ManagementFactory;

public class Main {
	Config Config = new Config();
	
	DNSServer DNSServer=null;
	OnionRouter Router = null;
	
	private long getMyIpid() {
		try {
			String st = ManagementFactory.getRuntimeMXBean().getName();
			String[] tok = st.split("\\@");
			return Long.parseLong(tok[0]);
			} catch(Exception E) { return 0; }
		
	}
	
	@SuppressWarnings("static-access")
	public void Start(String fc) throws Exception {
		try {
			Config = Config.LoadFromFile(fc);
			} catch(Exception E) {
			echo("Config error "+E.getMessage()+"\n");
			return;
			}
		echo("Start OnionRouter: ");
		Router = new OnionRouter(Config);
		echo("Ok\nStart DNS Server: ");
		DNSServer = new DNSServer(Config,Router);
		echo("Ok\nService Started\n");
		try {echo("Running at: ["+ManagementFactory.getRuntimeMXBean().getName()+"] "); } catch(Exception E) {}
		echo("Ok\n");
	}

public static void main(String args[]) 
      {
		Main N=null;
		try {
			String fc = "etc/tordns.conf";
			echo("\nTorDNS LocalProxy 1.0.1B\n\t(C) 2013 by EPTO (A)\n\tSome rights reserved\n\n");
			
			int cx = args.length;
			for (int ax=0;ax<cx;ax++) {
				boolean fm=false;
				String cmd = args[ax].toLowerCase().trim();		
				
				if (cmd.compareTo("-f")==0) { 
						fm=true;
						if ((ax+1)>=cx) {
							echo("Error in command line: -f\n\tFile required!\n");
							Helpex();
							return;
							}
						fc = args[ax+1]; 
						ax++;
						}
				
				if (cmd.compareTo("-?")==0 || cmd.compareTo("-h")==0) { 
						Helpex();  
						return; 
						}
				
				if (!fm) {
					echo("Invalid command line parameter `"+cmd+"`\n");
					Helpex(); 
					return;
					}
				
				}
			
			echo("Load Config '"+fc+"'\n");
			N = new Main();
			N.Start(fc);
			if (N.Config==null) { 
				echo("\nCan't start!\n");
				} else {
				if (N.Config.PidFile!=null) try { 
					file_put_bytes(N.Config.PidFile,Long.toString(N.getMyIpid()).getBytes());
					} catch(Exception EF) {
						echo("Wharning Can't write PID file `"+N.Config.PidFile+"` Error "+EF.getMessage()+"\n");
					}			
				}
		} catch(Exception E) { 
			if (N!=null && N.Config!=null) { 
				if (N.Config.Debug) EXC(E,"Main");
				} else EXC(E,"Main");
			echo("Fatal Error: "+E.getMessage()+"\n");
			}
      }

	private static void Helpex() {
		echo("\nUse:\n\tTorDNS -f <config file>\n\n");
		}	 

	public static void echo(String st) { System.out.print(st); }
	
	public  static void EXC(Exception E,String dove) {
		echo("\n\nException: "+dove+" = "+E.toString()+"\n"+E.getMessage()+"\n"+E.getLocalizedMessage()+"\n");
							StackTraceElement[] S = E.getStackTrace();
							for (int ax=0;ax<S.length;ax++) echo("STACK "+ax+":\t "+S[ax].toString()+"\n");
		}
	
	public static void file_put_bytes(String name,byte[]  data) throws Exception {
			FileOutputStream fo = new FileOutputStream(name);
			fo.write(data);
			fo.close();
		}	

}
