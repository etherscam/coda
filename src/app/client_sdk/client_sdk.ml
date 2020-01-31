(* sign_js.ml *)

(*[%%import
"/src/config.mlh"]

[%%ifdef
consensus_mechanism]

[%%error
"Client_sdk cannot be built if \"consensus_mechanism\" is defined"]

[%%endif]
 *)
open Coda_base_nonconsensus
open Signature_lib_nonconsensus
module Currency = Currency_nonconsensus.Currency
module Coda_numbers = Coda_numbers_nonconsensus.Coda_numbers
module Global_slot = Coda_numbers_nonconsensus.Global_slot
module Memo = User_command_memo
open Js_of_ocaml

type string_js = Js.js_string Js.t

type payload_common_js =
  < fee: string_js Js.prop
  ; nonce: string_js Js.prop
  ; valid_until: string_js Js.prop
  ; memo: string_js Js.prop >
  Js.t

type payment_payload_js =
  < receiver: string_js Js.prop ; amount: string_js Js.prop > Js.t

type payment_js =
  < common: payload_common_js Js.prop
  ; payment_payload: payment_payload_js Js.prop >
  Js.t

type stake_delegation_js =
  < common: payload_common_js Js.prop ; new_delegate: string_js Js.prop > Js.t

let get_payload_common (payload_common_js : payload_common_js) =
  let fee_js = payload_common_js##.fee in
  let fee = Js.to_string fee_js |> Currency.Fee.of_string in
  let nonce_js = payload_common_js##.nonce in
  let nonce = Js.to_string nonce_js |> Coda_numbers.Account_nonce.of_string in
  let valid_until_js = payload_common_js##.valid_until in
  let valid_until = Js.to_string valid_until_js |> Global_slot.of_string in
  let memo_js = payload_common_js##.memo in
  let memo = Js.to_string memo_js |> Memo.create_from_string_exn in
  User_command_payload.Common.Poly.{fee; nonce; valid_until; memo}

let _ =
  Js.export "codaSDK"
    (object%js (_self)
       (** generate a private key, public key pair *)
       method genKeys =
         let sk = Private_key.create () in
         let sk_str_js = sk |> Private_key.to_base58_check |> Js.string in
         let pk_str_js =
           Public_key.(
             of_private_key_exn sk |> compress |> Compressed.to_base58_check
             |> Js.string)
         in
         object%js
           val privateKey = sk_str_js

           val publicKey = pk_str_js
         end

       (** sign arbitrary string with private key *)
       method signString (sk_base58_check_js : string_js) (str_js : string_js)
           : Signature.t =
         let sk_base58_check = Js.to_string sk_base58_check_js in
         let sk = Private_key.of_base58_check_exn sk_base58_check in
         let str = Js.to_string str_js in
         (* TODO : how to encode return value for JS *)
         String_sign.Schnorr.sign sk str

       (** sign payment transaction payload with private key *)
       method signPayment (sk_base58_check_js : string_js)
           (payment_js : payment_js) =
         let sk_base58_check = Js.to_string sk_base58_check_js in
         let sk = Private_key.of_base58_check_exn sk_base58_check in
         let User_command_payload.Common.Poly.{fee; nonce; valid_until; memo} =
           get_payload_common payment_js##.common
         in
         let payment_payload = payment_js##.payment_payload in
         let receiver =
           Js.to_string payment_payload##.receiver
           |> Public_key.Compressed.of_base58_check_exn
         in
         let amount =
           Js.to_string payment_payload##.amount |> Currency.Amount.of_string
         in
         let body =
           User_command_payload.Body.Payment
             Payment_payload.Poly.{receiver; amount}
         in
         let payload =
           User_command_payload.create ~fee ~nonce ~valid_until ~memo ~body
         in
         (* TODO : how to encode return value for JS *)
         Schnorr.sign sk payload

       (** sign payment transaction payload with private key *)
       method signStakeDelegation (sk_base58_check_js : string_js)
           (stake_delegation_js : stake_delegation_js) =
         let sk_base58_check = Js.to_string sk_base58_check_js in
         let sk = Private_key.of_base58_check_exn sk_base58_check in
         let User_command_payload.Common.Poly.{fee; nonce; valid_until; memo} =
           get_payload_common stake_delegation_js##.common
         in
         let new_delegate =
           Js.to_string stake_delegation_js##.new_delegate
           |> Public_key.Compressed.of_base58_check_exn
         in
         let body =
           User_command_payload.Body.Stake_delegation
             Stake_delegation.(Set_delegate {new_delegate})
         in
         let payload =
           User_command_payload.create ~fee ~nonce ~valid_until ~memo ~body
         in
         (* TODO : how to encode return value for JS *)
         Schnorr.sign sk payload
    end)
