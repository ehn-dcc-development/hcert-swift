import XCTest
@testable import hcert
import SwiftCBOR

@available(OSX 11.0, *)
final class HcertTests: XCTestCase {
    func testHC1() {
        
        let barcodeNoZlib = "HC1RRQT 9O60GO0W-Q6N7PBBR538CKL05YOC.3E+70SH86ME$-CQEDSVD2B6OCCK/E0WD* CZED7WE93D5JE069-XB27BS5OGLCW700LAA195GR%:J5RQ-8GADEI-LDZ7QG33S7U2RJ BHAGQ/AQWFH3KI72NNRHBV/RF6+DJ5QW389 4P0O XSFRAF0G"
        
        // Generated with pem2json-kid.sh from  ehn-sign-verify-python-trivial
        //
        let trustJson = "[ {  \"kid\" : \"DEFBBA3378B322F5\", \"coord\" : [ \"230ca0433313f4ef14ec0ab0477b241781d135ee09369507fcf44ca988ed09d6\",\"bf1bfe3d2bda606c841242b59c568d00e5c8dd114d223b2f5036d8c5bc68bf5d\" ] }, {  \"kid\" : \"FFFBBA3378B322F5\", \"coord\" : [ \"9999a0433313f4ef14ec0ab0477b241781d135ee09369507fcf44ca988ed09d6\",\"9999fe3d2bda606c841242b59c568d00e5c8dd114d223b2f5036d8c5bc68bf5d\" ] }, {  \"kid\" : \"CCCFBBA3378B322F5\", \"coord\" : [ \"7799a0433313f4ef14ec0ab0477b241781d135ee09369507fcf44ca988ed09d6\",\"9999fe3d2bda606c841242b59c568d00e5c8dd114d223b2f5036d8c5bc68bf5d\" ] } ,{  \"kid\" : \"AAFBBA3378B322F5\", \"coord\" : [ \"8899a0433313f4ef14ec0ab0477b241781d135ee09369507fcf44ca988ed09d6\",\"9999fe3d2bda606c841242b59c568d00e5c8dd114d223b2f5036d8c5bc68bf5d\" ] }, {\"kid\" : \"D4FF3B70590B18B7\",        \"coord\" : [           \"fe3f6d97ec0010e7a8b35492662b8a35c19804bbe453f461ec51e37f13a27552\", \"9a3e457c8a8fe69f9f776bef8e76095029f960d077f78238f284452332f785b0\"]     }  ]"
        
        do {
            let decoder = HCert()
            try decoder.setJSONtrustlist(trustList: trustJson)
            
            let result = try decoder.decodeHC1(barcode: barcodeNoZlib)
            XCTAssertNotNil(result)
            XCTAssertTrue(result is CBOR)
            print("Correctly signed. Payload shown below:")
            print(result)
        } catch {
            print("Drat: \(error)")
            XCTAssert(1 == 2)
        }
    }

    static var allTests = [
        ("test HC1 decode", testHC1)
    ]
}
