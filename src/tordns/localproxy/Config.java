package tordns.localproxy;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


	public class Config {

		public int GarbageFreq = 2000;									//Frequenza di Garbage collector per le Onion e le connessioni inattive.
				
		public InetAddress DNSServer = null; 							//IP Server DNS
		public int DNSSoTimeout = 1000;									//Timeout richieste DNS al server
		public boolean DNSEnableMX = true;						//Abilita le onion MX (mail)
		public boolean DNSAddAMX = true;							//Forza A record in risporte MX
		public boolean DNSInAddr = true;								//Risponde a in-adds.arpa. per gli indirizzi locali.
				
		public int OnionTTL = 60000;										//TTL Per una onion
		public int MaxConnectionXPort = 10;							//Max. Connessioni per porta per onion
		public int MaxConnectionIdle=600000;						//TTL Per un proxy onion su una porta intattivo
		public int MaxHosts = 320;											//Max. num di onion contemporanee
		
		public NetArea LocalNetArea=null;								//Network loncale di assegnamento ip 127.0.0.0
		public InetAddress LocalNet = null;								//Indirizzo ip (rete) locale tipicamente 127.0.0.0
		public int LocalFisrtIp = 2;											//Numero del primo IP da assegnare 2 = 127.0.0.2
		public int LocalIPReleaseTime=5;									//Tempo di rilascio IP non utilizzati. (Secondi)
		
		public InetAddress TorIP = null;									//Indirizzo IP di tor 127.0.0.1
		public int TorPort= 9150;												//Porta SOCKS4A ti tor 9050
	
		public InetAddress[] NoIP = null;									//Lista IP da non usare in LocalNet
		public int[] NoPort = null;											//Lista di porte da non usare per le onion.
		
		public NetArea NetAllow = null;									//Rete in cui è consentito operare
		public InetAddress[] NetAllowIp = null;						//Ip che possono operare
		public InetAddress[] NetNoAllowIp = null;					//Ip che non possono operare
		public boolean NetDisallowAll=false;							//Disattiva tutto eccetto ciò che può
		
		public boolean DNSTorify = false;								//Tutto via tor
		public boolean DNSLogQuery = true;						//Logga query DNS
		
		public String IANAPortFile = null;
		public Map<String,Integer> PortName = new HashMap<>();
		public boolean UsePortName=false;
		
		public String LogFile = null;
		public String PidFile = null;
		
		public int DefaultPort = 80;											//Default port.
		public boolean Debug = false;									//Debug log
		public boolean LogStdout = false;								//Copia log in stdout
		
		public void Show() {
			String st="TorDNS Configuration:\n";
			st+="Server DNS\t"+DNSServer.toString()+"\n";
			st+="Local Net\t"+LocalNetArea.getString()+"\n";
			st+="Torify \t"+(DNSTorify ? "Yes" : "No")+"\n";
			st+="Tor:   \t"+TorIP.toString()+":"+this.TorPort+"\n";
			st+="Max Hosts:\t"+MaxHosts+"\n";
			st+="Port names:\t"+PortName.size()+"\n";
			st+="Default Disallow:\t" + (NetDisallowAll ? "Yes": "No")+"\n";
			st+="No Port:\t";
			for (int ax=0;ax<NoPort.length;ax++) st+=NoPort[ax]+" ";
			st+="\n";
			echo(st+"\n");
		}

		public static void echo(String st) { System.out.print(st); }
		
		@SuppressWarnings("resource")
		public static Config LoadFromFile(String filepath) throws Exception {
			DataInputStream in;
			BufferedReader br;
			Config C = new Config();
			C.LocalFisrtIp=0;
			C.MaxHosts=0;
			String RunBanner=null;
			boolean ShowInfo =false;
			
			FileInputStream F = new FileInputStream(filepath);
			int line=0;
	
			try {
					in = new DataInputStream(F);
					br = new BufferedReader(new InputStreamReader(in));
					String li = null;
					while((li=br.readLine())!=null) {
						line++;
						li = li.trim();
						if (li.length()==0) continue;
						if (li.charAt(0) =='#') continue;
						String[] tok = li.split("\\#",2);

						li = tok[0];
						li = li.trim();
						if (li.length()==0) continue;
						tok = li.split("\\s+");
						String cmd = tok[0].toLowerCase();
						boolean fc=false;
						
						if (cmd.compareTo("dnsserver")==0) { fc=true; C.DNSServer = ParseIp(tok[1]); }
						if (cmd.compareTo("torip")==0) { fc=true; C.TorIP = ParseIp(tok[1]); }
						if (cmd.compareTo("localnet")==0) {
							fc=true;
							C.LocalNetArea = ParseNet(tok[1]);
							C.LocalNet = C.LocalNetArea.getFirstIP();
							if (C.MaxHosts==0) C.MaxHosts = C.LocalNetArea.getMask() - 2;
							if (C.MaxHosts>65535) C.MaxHosts=65535;
							C.LocalFisrtIp = C.LocalNetArea.getNumberOfFirstIP();
							if (C.LocalFisrtIp==0) C.LocalFisrtIp=1;
							}
						
						if (cmd.compareTo("netallow")==0) {
							fc=true;
							if (tok[1].toLowerCase().contains("local")) C.NetAllow = C.LocalNetArea; 
							else if (tok[1].toLowerCase().contains("all")) C.NetAllow = null; 
							else C.NetAllow = ParseNet(tok[1]);
							}
						
						if (cmd.compareTo("logfile")==0) {
							fc=true;
								if (tok[1].toLowerCase().compareTo("stdout")==0) C.LogFile=null; else {
									C.LogFile=tok[1];
									try {
										File Fi = new File(C.LogFile);
										if (!Fi.exists()) Main.file_put_bytes(C.LogFile, new byte[] {32} );
										} catch(Exception EP) { throw new Exception("Log file error `"+tok[1]+"`"); }
									}
								}
						
						if (cmd.compareTo("pidfile")==0) {
							fc=true;
								if ("no nothing".contains(tok[1].toLowerCase())) C.LogFile=null; else C.PidFile=tok[1];
								}
						
						
						if (cmd.compareTo("runbanner")==0) {
								fc=true;
								String tk[] = li.split("\\s+",2);
								if (RunBanner==null) RunBanner="";
								RunBanner+="\n"+tk[1];
								}
						
						if (cmd.compareTo("portnames")==0) {fc=true; C.IANAPortFile = tok[1]; }
						if (cmd.compareTo("showinfo")==0) { fc=true; ShowInfo=Config.parseY(tok[1]); }
						if (cmd.compareTo("netdefaultdeny")==0) { fc=true; C.NetDisallowAll=Config.parseY(tok[1]); }
						if (cmd.compareTo("dnstorify")==0) { fc=true; C.DNSTorify=Config.parseY(tok[1]); }
						if (cmd.compareTo("dnslogquery")==0) { fc=true; C.DNSLogQuery=Config.parseY(tok[1]); }
						if (cmd.compareTo("dnssotimeout")==0) { fc=true; C.DNSSoTimeout=Integer.parseInt(tok[1]); }
						if (cmd.compareTo("defaultonionport")==0) { 
								fc=true; 
								C.DefaultPort=Integer.parseInt(tok[1]);
								if (C.DefaultPort<1 || C.DefaultPort>65535) throw new Exception("Invalid default port "+C.DefaultPort);
								}
						
						if (cmd.compareTo("onionttl")==0) { fc=true; C.OnionTTL=(int)(Integer.parseInt(tok[1])*1000); }
						if (cmd.compareTo("maxconnectionidle")==0) { fc=true; C.MaxConnectionIdle=(int)(Integer.parseInt(tok[1])*1000); }
						if (cmd.compareTo("maxhosts")==0) {
							fc=true;
								C.MaxHosts=(int)(Integer.parseInt(tok[1]));
								if (C.MaxHosts<4 || C.MaxHosts>65535) {
										F.close(); 
										throw new Exception("Invalid MaxHosts value! (From 4 to 65535)"); 
										}
								}
						if (cmd.compareTo("maxconnectionxport")==0) { fc=true; C.MaxConnectionXPort=(int)(Integer.parseInt(tok[1])); }
						if (cmd.compareTo("torport")==0) { fc=true; C.TorPort=(int)(Integer.parseInt(tok[1])); }
						if (cmd.compareTo("dnsenablemx")==0) { fc=true; C.DNSEnableMX = Config.parseY(tok[1]); }
						if (cmd.compareTo("dnsaddamx")==0) { fc=true;  C.DNSAddAMX = Config.parseY(tok[1]); }
						if (cmd.compareTo("dnsinaddr")==0) { fc=true; C.DNSInAddr = Config.parseY(tok[1]); }
						if (cmd.compareTo("debug")==0) { fc=true; C.Debug = Config.parseY(tok[1]); }
						if (cmd.compareTo("logtostdout")==0) { fc=true; C.LogStdout = Config.parseY(tok[1]); }
			
						if (cmd.compareTo("noports")==0) try {
							fc=true;
							C.NoPort = new int[tok.length-1];
							int t1 = C.NoPort.length;
							for (int t2=0;t2<t1;t2++) {
								C.NoPort[t2] = Integer.parseInt(tok[1+t2]);
								if (C.NoPort[t2]<0 || C.NoPort[t2]>65535) throw new Exception();
								}
							} catch(Exception FG) { throw new Exception("Invalid port"); }
						
						if (cmd.compareTo("nolocalip")==0) { fc=true; C.NoIP = ParseIPList(tok, false, true,"none empty nothing nobody unused"); }
						if (cmd.compareTo("netallowip")==0) { fc=true; C.NetAllowIp = ParseIPList(tok,true,true,"all"); }
						if (cmd.compareTo("netdenyip")==0) { fc=true; C.NetNoAllowIp = ParseIPList(tok,true,true,"none empty nothing nobody unused"); }
						if (cmd.length()==0) fc=true;
						if (!fc) throw new Exception("Unknown parameter `"+cmd+"`");
					}
					F.close();
					try {	in.close(); } catch(Exception FQ) {}
					try {	br.close(); } catch(Exception FQ) {}
					if (C.MaxHosts>C.LocalNetArea.getMask()) throw new Exception("MaxHosts is too big for the networkarea");
					if (C.MaxHosts>65535) throw new Exception("Too many MaxHost.\nSet another MaxHosts value!\n");
					if (C.MaxHosts==0) C.MaxHosts = C.LocalNetArea.getMask() - 2; 
					if (C.LocalFisrtIp==0) C.LocalFisrtIp=1;
					if (C.DNSServer==null) throw new Exception("DNSServer not set!");
					
					if (C.IANAPortFile==null || C.IANAPortFile.toLowerCase().compareTo("none")==0) {
						C.UsePortName=false;
						echo("\nWharning:\n\tDefault port name list, use a portfile via portnames parameter!\n\n");
					} else {
						try {
							echo("Load PortNames '"+C.IANAPortFile+"' ");
							LoadPortList(C);
							C.UsePortName=true;
							echo("\nNamed ports: "+C.PortName.size()+" Ok\n");
							
						} catch(Exception EP) {
							echo(EP.getMessage());
							C.UsePortName=false;
							throw new Exception("Configuration aborted!");
						}
					}
					
					int cx = C.NoPort.length;
					for (int ax=0;ax<cx;ax++) if (C.NoPort[ax]==C.DefaultPort) {
						echo("\nWharning:\t\nDefault onion port "+C.DefaultPort+" blocked by NoPort!\n\n");
						break;
						}
					
					if (ShowInfo) C.Show();
					
					if (RunBanner!=null) {
						RunBanner=RunBanner.replace("\\t", "\t");
						RunBanner=RunBanner.replace("\\r", "\r");
						RunBanner=RunBanner.replace("\\n", "\n");
						RunBanner=RunBanner.replace("\\b",new String(new byte[] {7}));
						RunBanner=RunBanner.replace("\\\\", "\\");
						echo(RunBanner+"\n");
						}
					
					return C;
			} catch(Exception E) {
				try {	F.close(); } catch(Exception FQ) {}
				String em = E.getMessage();
				if (em.compareTo("1")==0) em="Syntax Error";
				throw new Exception("Line: "+line+" "+em);
			}
		
		}
				
		private static InetAddress[] ParseIPList(String[] arr,boolean cannull,boolean canempty,String empty) throws Exception {
			int cx = arr.length;
			if (cx<1) {
					if (canempty) throw new Exception("Syntax error: set 1 or more ip address or `"+empty+"`"); else throw new Exception("Syntax error: set 1 or more ip address");
					}	
			
			if (cx==2 && empty.contains(arr[1].toLowerCase())) {
				if (!canempty) throw new Exception("This can't be empty or nothing!");
				if (cannull) return null; else return new InetAddress[0];
				}
			
			String last="???";
			try {
				
					InetAddress[] re = new InetAddress[arr.length-1];
							int t1 =re.length;
							for (int t2=0;t2<t1;t2++) {
								last=arr[t2+1];
								re[t2] = ParseIp(arr[t2+1]);
								}
							
					return re;	
			} catch(Exception E) { throw new Exception("Invalid IP address `"+last+"`"); }
			
		}
		
		private static boolean parseY(String s) throws Exception {
			s=s.trim();
			s=s.toLowerCase();
			if (s.compareTo("y")==0) return true;
			if (s.compareTo("yes")==0) return true;
			if (s.compareTo("true")==0) return true;
			if (s.compareTo("enabled")==0) return true;
			if (s.compareTo("enable")==0) return true;
			if (s.compareTo("1")==0) return true;
			if (s.compareTo("n")==0) return false;
			if (s.compareTo("no")==0) return false;
			if (s.compareTo("false")==0) return false;
			if (s.compareTo("disabled")==0) return false;
			if (s.compareTo("disable")==0) return false;
			if (s.compareTo("0")==0) return false;
			throw new Exception("Invalid boolean parameter `"+s+"`");
		}
		
		Config()  {
			try {
				DNSServer =null;
				LocalNet = InetAddress.getByAddress(new byte[] { 127,0,0,0 });
				
				TorIP = InetAddress.getByAddress(new byte[] { 127,0,0,1 });
				
				NoIP = new InetAddress[] { 
										InetAddress.getByAddress(new byte[] { 127,0,0,1}),
										InetAddress.getByAddress(new byte[] { 127,0,0,2})
										};
				
				NoPort = new int[] { 53 };
				} catch(Exception E) { EXC(E,"Conmfig"); }
			}
		
		private static InetAddress ParseIp(String st) throws Exception {
			try {
				String[] tok = st.split("\\.");
				if (tok.length!=4) throw new Exception();
				byte[] b = new byte[4];
				for (int ax=0;ax<4;ax++) {
					int c = Integer.parseInt(tok[ax]);
					if (c<0 || c>254) throw new Exception();
					b[ax]=(byte)(255&c);
				}
				return InetAddress.getByAddress(b);
				} catch(Exception E) {
					throw new Exception("Invalid IP Address `"+st+"`");
				}
		}
		
		private static NetArea ParseNet(String st) throws Exception {
			try {
				String[] tok = st.split("\\/");
				st=tok[0];
				int Nbt = Integer.parseInt(tok[1]);
				if (Nbt<1 || Nbt>31) throw new Exception();
				tok = st.split("\\.");
				if (tok.length!=4) throw new Exception();
				byte[] b = new byte[4];
				for (int ax=0;ax<4;ax++) {
					int c = Integer.parseInt(tok[ax]);
					if (c<0 || c>254) throw new Exception();
					b[ax]=(byte)(255&c);
				}
				//Nbt = 32-Nbt;
				if (Nbt<0 || Nbt>0xFFFFFFFFL) throw new Exception();
				return new NetArea( InetAddress.getByAddress(b) ,Nbt);
				
				} catch(Exception E) {
					throw new Exception("Invalid Network Area `"+st+"`");
				}
		}
		
		
		public void EXC(Exception E,String Dove) {
			String St = "FatalError `"+E.getMessage()+"` in `"+Dove+"`\n";
			Log(St);
		}
		
		public void Log(String St) {
			Date D = new Date();
			String h = (D.getYear()+1900)+"-"+(D.getMonth()+1)+"-"+D.getDate()+" "+D.getHours()+":"+D.getMinutes()+":"+D.getSeconds()+"."+(System.currentTimeMillis() % 1000);
			h+="                                                                                                                              ";
			h = h.substring(0, 25);
			St =h+"\t"+St.trim()+"\n";
			
			if (LogFile==null) echo(St); else {
				
				PrintWriter out = null;
					try {
					    out = new PrintWriter(new BufferedWriter(new FileWriter(LogFile, true)));
					    out.println(St);
					    if (LogStdout) echo(St);
					} catch (Exception e) {
					    echo("Log Error "+St);
					} finally {
					    if (out != null) {
					        try {
					            out.close();
					        } catch (Exception ignore) {
					        }
					    }
					}
				
			}
			
		}
		
		@SuppressWarnings("resource")
		private static void LoadPortList(Config C) throws Exception {
			String filepath = C.IANAPortFile;
			DataInputStream in=null;
			BufferedReader br=null;
			FileInputStream F=null;
			String li = null;
			int line=0;
	
			try {
				F = new FileInputStream(filepath);
				in = new DataInputStream(F);
				br = new BufferedReader(new InputStreamReader(in));
				} catch (Exception E) {
					try { br.close(); } catch(Exception Fg) {}
					try { in.close(); } catch(Exception Fg) {}
					try { F.close(); } catch(Exception Fg) {}
					throw new Exception("File error `"+filepath+"`");
				}
			
			try {	
				while((li=br.readLine())!=null) {
					line++;
					li = li.trim();
					if (li.length()==0) continue;
					if (li.charAt(0) =='#') continue;
					String[] tok = li.split("\\#",2);
					li = tok[0];
					li = li.trim();
					if (li.length()==0) continue;
					tok = li.split("\\s+");
					if (tok.length!=2) throw new Exception("Syntax error");
					String ports = tok[0].toLowerCase();
					String portn = tok[1];
					if (ports.length()<1 || ports.length()>8) throw new Exception("Invalid port name");
					int p =0;
					try {
						p = Integer.parseInt(portn);
						if (p<1 || p>65535) throw new Exception();
						} catch(Exception FG) {
							throw new Exception("Invalid port number `"+portn+"`");
							}
					if (C.PortName.containsKey(ports)) throw new Exception("Port arleady defined `"+ports+"`");
					C.PortName.put(ports,p);
					}
				} catch(Exception ER) {
					try { br.close(); } catch(Exception Fg) {}
					try { in.close(); } catch(Exception Fg) {}
					try { F.close(); } catch(Exception Fg) {}
					throw new Exception("Error in `"+filepath+"` Line "+line+": "+ER.toString());
				}
			
			br.close();
			in.close();
			F.close();
		}
		
	}