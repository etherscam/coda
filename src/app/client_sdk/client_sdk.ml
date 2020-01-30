(* sign_js.ml *)

[%%import
"/src/config.mlh"]

[%%ifdef
consensus_mechanism]

[%%error
"Client_sdk cannot be built if \"consensus_mechanism\" is defined"]

[%%endif]

open Js_of_ocaml

let _ =
  Js.export "codaSDK"
    (object%js (_self)
       method sign keys payload =
         Coda_base_nonconsensus.User_command.sign keys payload
    end)
