<?php
/**
 * @package   yii2-jwt [https://jwt.io]
 * @author    Rohit Suthar, Mumbai <rohisuthar@gmail.com>
 * @copyright Copyright &copy; Rohit Suthar, Mumbai, 2018
 * @version   1.0.0
 */

namespace rohitsuthar\jsonwebtoken;

use Yii;
use yii\base\Component;
use yii\base\Model;

class JWT extends Component {

    //build the signature and return the token
    public function generateToken($header_arr = [], $payout_arr = [], $secret) {
        $token = '';
        if (!empty($header_arr) && !empty($payout_arr) && !empty($secret)) {
            //build the signature
            $headers_encoded = self::base64url_encode(json_encode($header_arr));
            $payload_encoded = self::base64url_encode(json_encode($payout_arr));
            $signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret, true);
            $signature_encoded = self::base64url_encode($signature);

            //build and return the token
            $token = "$headers_encoded.$payload_encoded.$signature_encoded";
        }
        return $token;
    }

    //verify the encypted-token with secret key and return true or false
    public function verifyToken($algo, $jwt, $secret) {
        if (!empty($algo) && !empty($jwt) && !empty($secret)) {
            list($headerEncoded, $payloadEncoded, $signatureEncoded) = explode('.', $jwt);

            $dataEncoded = "$headerEncoded.$payloadEncoded";
            $signature = self::base64url_decode($signatureEncoded);
            $rawSignature = hash_hmac($algo, $dataEncoded, $secret, true);

            return hash_equals($rawSignature, $signature);
            exit;
        }
        return 0;
    }

    public function base64url_encode($data = '') {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public function base64url_decode($data = '') {
        $paddedData = '';
        if (!empty($data)) {
            $urlUnsafeData = strtr($data, '-_', '+/');
            $paddedData = str_pad($urlUnsafeData, strlen($data) % 4, '=', STR_PAD_RIGHT);
        }
        return base64_decode($paddedData);
    }

}

?>
