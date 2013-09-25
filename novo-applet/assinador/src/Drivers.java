
import java.util.ArrayList;
import java.util.Collection;

public class Drivers {
    public Collection<String> winDrivers(){
        Collection<String> drivers = new ArrayList<String>();
        drivers.add("C:/Windows/SysWOW64/cmP11.dll");
        drivers.add("c:/windows/system32/drivers/smclib.sys");
        drivers.add("c:/windows/system32/scardssp.dll");
        drivers.add("c:/windows/system32/scardsvr.dll");
        drivers.add("c:/windows/system32/ngp11v211.dll");
        drivers.add("c:/windows/system32/aetpkss1.dll");
        drivers.add("c:/windows/system32/gclib.dll");
        drivers.add("c:/windows/system32/pk2priv.dll");
        drivers.add("c:/windows/system32/w32pk2ig.dll");
        drivers.add("c:/windows/system32/eTPkcs11.dll");
        drivers.add("c:/windows/system32/acospkcs11.dll");
        drivers.add("c:/windows/system32/dkck201.dll");
        drivers.add("c:/windows/system32/dkck232.dll");
        drivers.add("c:/windows/system32/cryptoki22.dll");
        drivers.add("c:/windows/system32/acpkcs.dll");
        drivers.add("c:/windows/system32/slbck.dll");
        drivers.add("c:/windows/system32/cmp11.dll");
        drivers.add("c:/windows/system32/WDPKCS.dll");
        drivers.add("c:/windows/system32/scard32.dll");
        drivers.add("c:/windows/system32/scardssp.dll");
        drivers.add("c:/windows/system32/mcscm.dll");
        drivers.add("c:/windows/System32/Watchdata/Watchdata Brazil CSP v1.0/WDPKCS.dll");
        drivers.add("c:/Arquivos de programas/Gemplus/GemSafe Libraries/BIN/gclib.dll");
        drivers.add("c:/Program Files/Gemplus/GemSafe Libraries/BIN/gclib.dll");
        return drivers;
    }
    
     public Collection<String> linuxDrivers(){
        Collection<String> drivers = new ArrayList<String>();
        drivers.add("/usr/lib/libeTPkcs11.so");
        drivers.add("/usr/lib64/libeTPkcs11.so");
        drivers.add("/usr/lib/libeToken.so");
        drivers.add("/usr/lib/libeToken.so.4");
        drivers.add("/usr/lib/libaetpkss.so");
        drivers.add("/usr/lib/libgpkcs11.so");
        drivers.add("/usr/lib/libgpkcs11.so.2");
        drivers.add("/usr/lib/libepsng_p11.so");
        drivers.add("/usr/lib/libepsng_p11.so.1");
        drivers.add("/usr/local/ngsrv/libepsng_p11.so.1");
        drivers.add("/usr/lib/libcmP11.so");
        drivers.add("/usr/lib/libwdpkcs.so");
        drivers.add("/usr/local/lib64/libwdpkcs.so");
        drivers.add("/usr/local/lib/libwdpkcs.so");
        drivers.add("/usr/lib/watchdata/ICP/lib/libwdpkcs_icp.so");
        drivers.add("/usr/lib/watchdata/lib/libwdpkcs.so");
        drivers.add("/opt/watchdata/lib64/libwdpkcs.so");
        drivers.add("/usr/lib/opensc-pkcs11.so");
        drivers.add("/usr/lib/pkcs11/opensc-pkcs11.so");
        drivers.add("/usr/lib/libwdpkcs.dylib");
        drivers.add("/usr/local/lib/libwdpkcs.dylib");
        drivers.add("/usr/local/ngsrv/libepsng_p11.so.1.2.2");
        return drivers;
    }
     
    public Collection<String> macDrivers(){
        Collection<String> drivers = new ArrayList<String>();
        drivers.add("/usr/local/lib/libaetpkss.dylib");
        drivers.add("/usr/local/lib/libeToken.dylib");
        drivers.add("/usr/local/lib/libgpkcs11.dylib");
        drivers.add("/usr/local/lib/libgpkcs11.so.2");
        drivers.add("/usr/local/lib/libepsng_p11.so");
        drivers.add("/usr/local/lib/libepsng_p11.so.1");
        drivers.add("/usr/local/lib/libepsng_p11.so.1");
        drivers.add("/usr/local/lib/libeTPkcs11.dylib");
        drivers.add("/usr/local/lib/libeToken.so.4");
        drivers.add("/usr/local/lib/libcmP11.dylib");
        drivers.add("/usr/local/lib/libwdpkcs.dylib");
        drivers.add("/usr/local/lib/opensc-pkcs11.dylib");
        drivers.add("/usr/local/lib/opensc-pkcs11.dylib");
        drivers.add("/usr/local/lib/libwdpkcs.dylib");
        return drivers;
    }
}
