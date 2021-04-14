
import CryptoKit
import Foundation
import OSLog
import SwiftCBOR
import GRPC
import NIO

extension String {
    func fromBase45()->Data {
        let BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
        var d = Data()
        var o = Data()
        
        for c in self {
            if let at = BASE45_CHARSET.firstIndex(of: c) {
                let idx  = BASE45_CHARSET.distance(from: BASE45_CHARSET.startIndex, to: at)
                d.append(UInt8(idx))
            }
        }
        for i in stride(from:0, to:d.count, by: 3) {
            var x : UInt32 = UInt32(d[i]) + UInt32(d[i+1])*45
            if (d.count - i >= 3) {
                x += 45 * 45 * UInt32(d[i+2])
                o.append(UInt8(x / 256))
                o.append(UInt8(x % 256))
            } else {
                o.append(UInt8(x % 256))
            }
        }
        return o
    }
}

extension String: Error {}

extension StringProtocol {
    var hexaData: Data { .init(hexa) }
    var hexaBytes: [UInt8] { .init(hexa) }
    private var hexa: UnfoldSequence<UInt8, Index> {
        sequence(state: startIndex) { startIndex in
            guard startIndex < self.endIndex else { return nil }
            let endIndex = self.index(startIndex, offsetBy: 2, limitedBy: self.endIndex) ?? self.endIndex
            defer { startIndex = endIndex }
            return UInt8(self[startIndex..<endIndex], radix: 16)
        }
    }
}

@available(OSX 11.0, *)
class HCert {
    var trustList : String
    var trust : [[String: Any]]
    
    init(trustList: String) throws {
        self.trustList = trustList
        trust = try (JSONSerialization.jsonObject(with: trustList.data(using: .utf8)!, options: [])
                        as? [[String: Any]])!
    }
    
    let logger = Logger()
    let COSE_TAG = UInt64(18)
    let COSE_PHDR_SIG = CBOR.unsignedInt(1)
    let COSE_PHDR_KID = CBOR.unsignedInt(4)
    let COSE_PHDR_SIG_ES256 = CBOR.negativeInt(6 /* Value is -7 -- ECDSA256 with a NIST P256 curve */)
    let COSE_CONTEXT_SIGN1 = "Signature1" /// magic value from RFC8152 section 4.4
    let ZLIB_HDR = 0x78 /* Magic ZLIB header constant (see file(8)) */
    
    private func getPublicKeyByKid( kid : [UInt8]) -> [P256.Signing.PublicKey] {
        var pks : [P256.Signing.PublicKey] = []
        
        for case let elem : Dictionary in trust {
            if (kid == (elem["kid"] as! String).hexaBytes) {
                
                let x : [UInt8] = ((elem["coord"] as! Array<Any>)[0] as! String).hexaBytes
                let y : [UInt8] = ((elem["coord"] as! Array<Any>)[1] as! String).hexaBytes
                
                var rawk : [UInt8] = [ 04 ]
                rawk.append(contentsOf:x)
                rawk.append(contentsOf:y)
                if (rawk.count != 1+32+32) {
                    logger.info("Entry for \(kid) in the trust list malformed(ignored)")
                    continue;
                }
                
                pks.append(try! P256.Signing.PublicKey(x963Representation:rawk))
            }
        }
        return pks
    }
    
    private func getPublicKeysFromFile(file : String) -> [P256.Signing.PublicKey] {
        let pk = try! String(contentsOfFile:"dsc-worker.pub", encoding: .ascii)
        return [try! P256.Signing.PublicKey(pemRepresentation: pk)]
    }
    
    public func decodeHC1(barcode : String) throws -> Any  {
        var bc = barcode
        
        // Remove HC1 header
        if (bc.hasPrefix("HC1")) {
            bc = String(bc.suffix(bc.count-3))
        }
        
        // Decode base45 / base64
        //
        var raw : Data = bc.fromBase45()
        if (raw[0] == ZLIB_HDR) {
            // Decompress it.
            //
            var compressed = ByteBufferAllocator().buffer(bytes: raw)
            
            let inflate = Zlib.Inflate(format: Zlib.CompressionFormat.deflate,
                                       limit: .absolute(8 * 1024))
            var decompressed = ByteBufferAllocator().buffer(capacity: 32 * 1024)
            let decompressedBytesWritten = try inflate.inflate(&compressed, into: &decompressed)
            raw = decompressed.getBytes(at: 0, length: decompressedBytesWritten) ?? []
        };

        // CBOR decode this (Really COSE wrapper AKA CWT)
        //
        let cose = try CBORDecoder(input: [UInt8](raw)).decodeItem()!
        
        if case let CBOR.tagged(tag, cborElement) = cose {
            switch tag.rawValue {
            case COSE_TAG: // COSE Sign1 structure (as expecte)
                if case let CBOR.array(coseElements) = cborElement {
                    var kid : [UInt8] = []
                    
                    if (coseElements.count != 4) {
                        throw "Not a COSE array"
                    }
                    
                    guard case let CBOR.byteString(shdr) = coseElements[0],
                          let protected = try? CBOR.decode(shdr),
                          case let CBOR.byteString(byteArray) = coseElements[2],
                          let payload = try? CBOR.decode(byteArray),
                          case let CBOR.byteString(signature) = coseElements[3]
                    else {
                        throw "Not a (complete) COSE data structure. Did you use Python 2.7? "
                    }
                    
                    // Best effort extraction of the KID from the unprotected header.
                    //
                    if case let CBOR.byteString(uhdr) = coseElements[1], let  unprotected = try? CBOR.decode(uhdr) {
                        if case let CBOR.map(map) = unprotected {
                            if case let CBOR.byteString(k) = map[COSE_PHDR_KID]!  {
                                kid = k
                            }
                        }
                    }
                    
                    if case let CBOR.map(map) = protected {
                        let k = map[COSE_PHDR_SIG]!
                        
                        //  Single ECDSA Signature (ECDSA 256:-7 (shows as negativeInt(6))
                        //
                        if (k != COSE_PHDR_SIG_ES256) {
                            throw "Not a ECDSA NIST P-256 signature"
                        }
                        
                        // protect KID always wins from unprotected (as the latter is not signed.
                        //
                        if case let CBOR.byteString(k) = map[COSE_PHDR_KID]!  {
                            kid = k
                        }
                    }
                    
                    let externalData = CBOR.byteString([]) // nil string - need to an empty byte buffer, not a nil or an empty array.
                    let signed_payload : [UInt8] = CBOR.encode(["Signature1",coseElements[0],externalData,coseElements[2]])
                    let digest = SHA256.hash(data:signed_payload)

                    let signatureForData = try! P256.Signing.ECDSASignature.init(rawRepresentation: signature)

                    // publicKeys = getPublicKeyFromFile(file: "dsc-worker.pub")
                    let publicKeys = getPublicKeyByKid(kid: kid)
                    
                    // This needs to be a loop - as KIDs and similar are not guaranteed unqiue.
                    //
                    for pk in publicKeys {
                        if (pk.isValidSignature(signatureForData, for: digest)) {
                            return payload
                        }
                    }
                    throw "Could not validate the signature with the current trust list"
                };
            default:
                throw "Not a COSE Sign1(18) message"
            };
        }
        throw "Error processing COSE"
    }
}

