package tordns.localproxy;


public class XOnionParser {
		public String Onion = "";
		public String Key = "";
		public int Port = 80;
		public String Tld="";
		public String Full="";
		private Config Config = null;
		XOnionParser(Config C) {
			Config=C;
			Port=C.DefaultPort;
		}
		
		public static XOnionParser fromString(Config C,String Onion) throws Exception {
		XOnionParser Q = new XOnionParser(C);
		Onion=Onion.toLowerCase();
		Onion=Onion.trim();
		String[] tok = Onion.split("\\.");
		int cx = tok.length;
		if (cx<2) throw new Exception("XOnionParser: Invalid host "+Onion);	
		if (tok[cx-1].length()==0) cx--;
		String sport = null;
		if (cx>2) sport = tok[cx-3]; else sport=""+C.DefaultPort;
		Q.Port=80;
		if (sport.matches("[0-9]+")) {
			sport=sport.trim();
			try { Q.Port = Integer.parseInt(sport); } catch(Exception E) { C.Log("XOnionParser: Invalid proto "+sport+"\n"); }
			} else {
				sport=sport.toLowerCase().trim();
				if (!C.PortName.containsKey(sport)) {
					Q.Port=C.DefaultPort;
					C.Log("XOnionParser: Unknown proto `"+sport+"`\n"); 
				} else {
					Q.Port = C.PortName.get(sport);
				}
			}
		Q.Tld = tok[cx-1];		
		Q.Key =tok[cx-2];
		Q.Onion = Q.Key+"."+Q.Tld;
		Q.Full = Integer.toString(Q.Port)+"."+Q.Key+"."+Q.Tld;
		return Q;
		}
		
		public String toString() { return Port+"."+Key+"."+Tld; }
}
