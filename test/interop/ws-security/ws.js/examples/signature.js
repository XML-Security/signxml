var ws = require('ws.js')
, fs = require('fs')
, sec = ws.Security
, X509BinarySecurityToken = ws.X509BinarySecurityToken
, FileKeyInfo = require('xml-crypto').FileKeyInfo


var x509 = new X509BinarySecurityToken(
  { "key": fs.readFileSync("client.pem").toString()})
var signature = new ws.Signature(x509)
signature.addReference("//*[local-name(.)='Body']")
signature.addReference("//*[local-name(.)='Timestamp']")

//validateResponseSignature determines if we should validate any incoming signature.
var sec = new ws.Security({"validateResponseSignature": true},
  [ x509,
  signature
  ])

//only required if you specified validateResponseSignature as true
sec.options.responseKeyInfoProvider = new FileKeyInfo("server_public.pem")

var handlers =
  [ new ws.Addr("http://www.w3.org/2005/08/addressing")
  , sec
  , new ws.Http()
  ]

request = "<Envelope xmlns='http://schemas.xmlsoap.org/soap/envelope/'>" +
          "<Header />" +
            "<Body>" +
              "<GetData xmlns='http://tempuri.org/'>" +
                "<value>123</value>" +
              "</GetData>" +
            "</Body>" +
          "</Envelope>"

var ctx =   { request: request
  , url: "http://localhost:7171/Service/sign_body_timestamp_wsa"
  , action: "http://tempuri.org/IService/GetData"
  , contentType: "text/xml"
}

ws.send(handlers, ctx, function(ctx) {
  console.log("status " + ctx.statusCode)
  console.log("messagse " + ctx.response)
})
