var ws = require('ws.js')

request = "<Envelope xmlns='http://schemas.xmlsoap.org/soap/envelope/'>" +
          "<Header />" +
            "<Body>" +
              "<GetData xmlns='http://tempuri.org/'>" +
                "<value>123</value>" +
              "</GetData>" +
            "</Body>" +
          "</Envelope>"

var ctx =  { request: request
           , url: "http://localhost:7171/Service/soap11wsa0408" //can also send to www.google.com if just testing the pipeline
           , action: "http://tempuri.org/IService/GetData"
           , contentType: "text/xml"
           }


var handlers =  [ new ws.Addr("http://schemas.xmlsoap.org/ws/2004/08/addressing")
                , new ws.Http()
                ]

ws.send(handlers, ctx, function(ctx) {
  console.log("response: " + ctx.response);
})
