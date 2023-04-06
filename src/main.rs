use std::{ffi::c_void, mem::transmute};

use windows::{Win32::{Security::Cryptography::{UI::{CERT_SELECT_STRUCT_W, self, CSS_ENABLETEMPLATE},
                CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCATION_SHIFT, CERT_SYSTEM_STORE_CURRENT_USER_ID,
                CERT_QUERY_ENCODING_TYPE, HCRYPTPROV_LEGACY, CERT_OPEN_STORE_FLAGS, CertOpenStore, CERT_CONTEXT, CertFreeCertificateContext, CertCloseStore, CERT_CLOSE_STORE_CHECK_FLAG},
                System::LibraryLoader::{LoadLibraryW, GetProcAddress}}, w, s
            };


type CertSelectCertificateW = extern "stdcall" fn(*const CERT_SELECT_STRUCT_W);
fn main() -> ::windows::core::Result<()> {
    unsafe {

        let mut fresh_cert: *mut CERT_CONTEXT = ::core::mem::zeroed();
        let crypt_ui_instance = LoadLibraryW(w!("cryptdlg.dll"))?;
        let store_name = w!("My").as_ptr() as *const c_void;
        let mut personal_store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W,
            CERT_QUERY_ENCODING_TYPE::default(),
            HCRYPTPROV_LEGACY::default(),
            CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT),
            Some(store_name))?;
        
        let cert_select_struct = CERT_SELECT_STRUCT_W {
                dwSize: std::mem::size_of::<CERT_SELECT_STRUCT_W>() as u32,
                hwndParent: ::core::mem::zeroed(),
                hInstance: crypt_ui_instance,
                pTemplateName: w!(""),
                dwFlags: CSS_ENABLETEMPLATE,
                szTitle: w!("Certificate to sign .exe"),
                cCertStore: 1,
                arrayCertStore: &mut personal_store,
                // code signing 
                szPurposeOid: s!("1.3.6.1.5.5.7.3.3"),
                cCertContext: 0,
                arrayCertContext: &mut fresh_cert,
                lCustData: windows::Win32::Foundation::LPARAM(0),
                pfnHook: UI::PFNCMHOOKPROC::None,
                pfnFilter: UI::PFNCMFILTERPROC::None,
                szHelpFileName: w!(""),
                dwHelpId: 0,
                hprov: 0,
            };

        let cert_select_certificate_w: CertSelectCertificateW = transmute(
            GetProcAddress(crypt_ui_instance, s!("CertSelectCertificateW")));
        cert_select_certificate_w(&cert_select_struct);
        if fresh_cert.is_null() { std::process::exit(1); }

        let mut extended_sign_info: UI::CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO = UI::CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO {
            dwSize: std::mem::size_of::<UI::CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO>() as u32,
            dwAttrFlags: UI::CRYPTUI_WIZ_DIGITAL_SIGN_INDIVIDUAL,
            pwszDescription: w!(""),
            pwszMoreInfoLocation: w!(""),
            pszHashAlg: s!(""),
            pwszSigningCertDisplayString: w!("Sign the EXE"),
            hAdditionalCertStore: ::core::mem::zeroed(),
            psAuthenticated: ::core::mem::zeroed(),
            psUnauthenticated: ::core::mem::zeroed(),
        };
        let sign_info: UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO = UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO {
            dwSize: std::mem::size_of::<UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO>() as u32,
            dwSubjectChoice: windows::Win32::Security::Cryptography::UI::CRYPTUI_WIZ_DIGITAL_SIGN_SUBJECT(0),
            Anonymous1: UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO_0{ pwszFileName: w!("") },
            dwSigningCertChoice: UI::CRYPTUI_WIZ_DIGITAL_SIGN_CERT,
            Anonymous2: UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO_1 { pSigningCertContext: fresh_cert },
            pwszTimestampURL: w!("http://timestamp.sectigo.com"),
            //pwszTimestampURL: w!("http://sha256timestamp.ws.symantec.com/sha256/timestamp"),
            dwAdditionalCertChoice: UI::CRYPTUI_WIZ_DIGITAL_ADDITIONAL_CERT_CHOICE(0),
            pSignExtInfo: &mut extended_sign_info as *mut UI::CRYPTUI_WIZ_DIGITAL_SIGN_EXTENDED_INFO,
        };
        // Call exe siganture UI with cert selected above
        let show_me_signature = UI::CryptUIWizDigitalSign(
            0,
            None,
            w!("Sign the EXE"),
            &sign_info as *const UI::CRYPTUI_WIZ_DIGITAL_SIGN_INFO, 
            ::core::mem::zeroed(), 
        );
        if show_me_signature.as_bool() { println!("Sign Good") } else { println!("Sign Bad") }
        if !CertFreeCertificateContext(Some(fresh_cert)).as_bool() {
            println!("Couldn't close the cert context.");
        }
        if !CertCloseStore(personal_store, CERT_CLOSE_STORE_CHECK_FLAG).as_bool() {
            println!("Couldn't close the store.");
        }

    }
    Ok(())

}