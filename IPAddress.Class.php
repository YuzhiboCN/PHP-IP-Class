class IPAddress{
        /**
         * 获取客户端IP地址
         * Get Client IP
         * @return string IP地址
         */
        static function GetClientIP(){
            if(getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'),'unknown'))
                $IP = getenv('HTTP_CLIENT_IP');
            else if(getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'),'unknown'))
                $IP = getenv('HTTP_X_FORWARDED_FOR');
            else if(getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'),'unknown'))
                $IP = getenv('REMOTE_ADDR');
            else if(isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'],'unknown'))
                $IP = $_SERVER['REMOTE_ADDR'];
            else $IP = 'unknown';
            return $IP;
        }

        /**
         * 获取服务器IP地址
         * Get Server IP
         * @return string IP地址
         */
        static function GetServerIP(){
            if(isset($_SERVER))
                if($_SERVER['SERVER_ADDR'])
                    $IP=$_SERVER['SERVER_ADDR'];
                else
                    $IP=$_SERVER['LOCAL_ADDR'];
            else
                $IP=getenv('SERVER_ADDR');
            return $IP;
        }

        /**
         * 获取IP信息
         * Get IP info from WebAPI
         * @param string $IP
         * @return array
         */
        static function GetIPInfo(string $IP=''){
            $CURL=curl_init('http://ip-api.com/json/'.$IP);
            curl_setopt_array($CURL,array(
                CURLOPT_RETURNTRANSFER=>true,
                CURLOPT_CUSTOMREQUEST=>'GET'
            ));
            $CurlResult=curl_exec($CURL);
            curl_close($CURL);
            return json_decode($CurlResult,true);
        }

        /**
         * CIDR地址转IP地址
         * CIDR to IP Array
         * @param string $CIDR CIDR地址
         * @return array
         */
        static function CIDRToIP(string $CIDR){
            preg_match("/(.*)\/(\d{1,3})/si",$CIDR,$Info);
            return $Info?array('IP'=>$Info[1],'Mask'=>(int)$Info[2]):array();
        }

        /**
         * IP地址转CIDR地址
         * CIDR to IP Array
         * @param array $IPArr IP地址
         * @return string
         */
        static function IPToCIDR(array $IPArr){
            return $IPArr['IP'].'/'.$IPArr['Mask'];
        }

        /**
         * 获取网络号
         * Get NetworkNumber
         * @param string $IP IP地址
         * @param int $Mask 子网掩码
         * @param bool $Binary 是否使用二进制表示
         * @return string
         * @throws Exception
         */
        static function GetNetNum(string $IP,int $Mask,bool $Binary=false){
            switch (self::GetIPVersion($IP)){
                case 4:
                    if ($Mask<0 or $Mask>32)
                        throw new Exception('子网掩码超出范围!');
                    $NetNum=ip2long($IP)>>(32-$Mask)<<(32-$Mask);
                    return $Binary?str_pad(decbin($NetNum),32,'0',STR_PAD_RIGHT):long2ip($NetNum);
                    break;
                case 6:
                    if ($Mask<0 or $Mask>128)
                        throw new Exception('子网掩码超出范围!');
                    if ($Mask==128)
                        return strtoupper($IP);
                    $IPArr=explode('.',self::IPv6CHNToDDN($IP));
                    $Group=intdiv($Mask,32);
                    $IPv6_DDN_Prefix=implode('.',array_slice($IPArr,0,$Group*4));
                    $IPv6_DDN_Middle=self::GetNetNum(implode('.',array_slice($IPArr,$Group*4,4)),$Mask%32);
                    $IPv6_DDN_Suffix=implode('.',array_fill(0,(3-$Group)*4,0));
                    return self::IPv6DDNToCHN($IPv6_DDN_Prefix.'.'.$IPv6_DDN_Middle.'.'.$IPv6_DDN_Suffix);
                default:
                    return '';
            }
        }

        /**
         * 通过CIDR获取网络号
         * Get NetworkNumber use CIDR
         * @param string $CIDR IP地址
         * @param bool $Binary 是否使用二进制表示
         * @return string
         * @throws Exception
         */
        static function GetNetNumCIDR(string $CIDR,bool $Binary=false){
            if (!$IPInfo=self::CIDRToIP($CIDR)) return '';
            return self::GetNetNum($IPInfo['IP'],(int)$IPInfo['Mask'],$Binary);
        }

        /**
         * 获取主机号
         * Get HostNumber
         * @param string $IP IP地址
         * @param int $Mask 子网掩码
         * @param bool $Binary 是否使用二进制表示
         * @return string
         * @throws Exception
         */
        static function GetHostNum(string $IP,int $Mask,bool $Binary=false){
            switch (self::GetIPVersion($IP)){
                case 4:
                    if ($Mask<0 or $Mask>32)
                        throw new Exception('子网掩码超出范围!');
                    $HostNum=ip2long(self::GetNetNum($IP,$Mask))^ip2long($IP);
                    return $Binary?str_pad(decbin($HostNum),32,'0',STR_PAD_LEFT):long2ip($HostNum);
                    break;
                case 6:
                    if ($Mask<0 or $Mask>128)
                        throw new Exception('子网掩码超出范围!');
                    if ($Mask==128)
                        return strtoupper($IP);
                    $IPArr=explode('.',self::IPv6CHNToDDN($IP));
                    $Group=intdiv($Mask,32);
                    $IPv6_DDN_Prefix=implode('.',array_fill(0,$Group*4,0));
                    $IPv6_DDN_Middle=self::GetHostNum(implode('.',array_slice($IPArr,$Group*4,4)),$Mask%32);
                    $IPv6_DDN_Suffix=implode('.',array_slice($IPArr,($Group+1)*4));
                    return self::IPv6DDNToCHN($IPv6_DDN_Prefix.'.'.$IPv6_DDN_Middle.'.'.$IPv6_DDN_Suffix);
                    break;
                default:
                    return '';
            }
        }

        /**
         * 获取主机号CIDR
         * Get HostNumber usr CIDR
         * @param string $CIDR IP地址
         * @param bool $Binary 是否使用二进制表示
         * @return string
         * @throws Exception
         */
        static function GetHostNumCIDR(string $CIDR,bool $Binary=false){
            if (!$IPInfo=self::CIDRToIP($CIDR)) return '';
            return self::GetHostNum($IPInfo['IP'],$IPInfo['Mask'],$Binary);
        }

        /**
         * 匹配IP的网络号是否相同
         * Match NetworkNumber
         * @param string | array ...$IP IP|IPArr
         * @return bool
         * @throws Exception
         */
        static function MatchNetNum(...$IP){
            $NetNumArr=array();
            foreach ($IP as $Value)
                array_push($NetNumArr,self::GetNetNumCIDR(is_array($Value)?self::IPToCIDR($Value):$Value));
            return count(array_unique($NetNumArr))==1;
        }

        /**
         * 判断样本IP是否在模板IP的子网中
         * Is in Network
         * @param string | array $NetNum 网络号
         * @param string | array ...$Sample 样本
         * @return bool
         * @throws Exception
         */
        static function InNetNum($NetNum,...$Sample){
            $Template=is_array($NetNum)?$NetNum:self::CIDRToIP($NetNum);
            foreach ($Sample as $Value){
                if (!$Sample=is_array($Value)?$Value:self::CIDRToIP($Value))
                    return false;
                if($Sample['Mask']<$Template['Mask'])
                    return false;
                $Sample['Mask']=$Template['Mask'];
                if(self::MatchNetNum($Template,$Sample))
                    return true;
            }
            return false;
        }

        /**
         * 获取IP地址版本
         * Get ip version
         * @param string $IP
         * @return int 4|6
         */
        static function GetIPVersion(string $IP=''){
            return strstr($IP,':')?6:4;
        }

        /**
         * 检查是否为IPv4地址
         * Is IPv4
         * @param string $IPv4 IPv4地址
         * @return bool
         */
        static function IPv4Check(string $IPv4=''){
            return filter_var($IPv4,FILTER_VALIDATE_IP,FILTER_FLAG_IPV4);
        }

        /**
         * 检查是否为IPv6地址
         * Is IPv6
         * @param string $IPv6 IPv6地址
         * @return bool
         * @throws Exception
         */
        static function IPv6Check(string $IPv6=''){
            return filter_var($IPv6,FILTER_VALIDATE_IP,FILTER_FLAG_IPV6);
        }

        /**
         * IPv6转全写
         * IPv6 Abbreviation to Full
         * @param string $IPv6 IPv6地址
         * @return string IPv6全写
         * @throws Exception
         */
        static function IPv6ToFull(string $IPv6=''){
            $IPStr='';
            if (!self::IPv6Check($IPv6)) throw new Exception('IP地址格式错误!');
            $IPArr=explode(':',$IPv6);
            $NullKey=array_search('',$IPArr);
            for ($Key=0;$Key<count($IPArr);$Key++)
                if ($Key===$NullKey)
                    for ($Num=8-count($IPArr);$Num>=0;$Num--)
                        $IPStr.='0000:';
                else $IPStr.=sprintf('%04s:',$IPArr[$Key]);
            return rtrim(strtoupper($IPStr),':');
        }

        /**
         * IPv6转简写
         * IPv6 Full to Abbreviation
         * @param string $IPv6 IPv6地址
         * @return string IPv6简写
         * @throws Exception
         */
        static function IPv6ToAbbreviation(string $IPv6=''){
            $IPStr='';
            $IPArr=explode(':',self::IPv6ToFull($IPv6));
            $KeyArrZero=array();
            $KeyArrZero_Max=array();
            $KeyGroupID=0;
            $KeyLastZreo=-1;

            $IPArr=array_map(function ($Value){
                if (hexdec($Value)==0) return '0';
                else return ltrim($Value,'0');
            },$IPArr);
            foreach ($IPArr as $Key=>$IP){
                if ($IP=='0'){
                    $KeyLastZreo=$Key;
                    $KeyArrZero[$KeyGroupID][]=$Key;
                }else if ($Key-$KeyLastZreo==1){
                    $KeyLastZreo=$Key;
                    $KeyGroupID++;
                }
            }
            if ($KeyArrZero){
                foreach ($KeyArrZero as $Value)
                    if (count($Value)>count($KeyArrZero_Max))
                        $KeyArrZero_Max=$Value;
                $IPArr[array_pop($KeyArrZero_Max)]=':';
                foreach ($KeyArrZero_Max as $Key)
                    unset($IPArr[$Key]);
            }
            foreach ($IPArr as $Key=>$IP){
                if ($IP==':') $IPStr=rtrim($IPStr,':');
                $IPStr.=$IP.(($Key==7 and $IP!=':')?'':':');
            }

            return $IPStr;
        }

        /**
         * IPv6转十六进制字符串
         * IPv6 colon hexadecimal notation to hexadecimal string
         * @param string $IPv6 IPv6地址
         * @return string 十六进制字符串
         * @throws Exception
         */
        static function IPv6CNHToHEX(string $IPv6=''){
            return preg_replace('/[:]+/i','',self::IPv6ToFull($IPv6));
        }

        /**
         * IPv6冒分十六进制转点分十进制
         * IPv6 colon hexadecimal notation to dotted decimal notation
         * @param string $IPv6 IPv6地址
         * @return string 点分十进制
         * @throws Exception
         */
        static function IPv6CHNToDDN(string $IPv6=''){
            return implode('.',array_map(function ($Value){
                return hexdec($Value);
            },str_split(self::IPv6CNHToHEX($IPv6),2)));
        }

        /**
         * IPv6点分十进制转冒分十六进制
         * IPv6 dotted decimal notation to colon hexadecimal notation
         * @param string $DDN 点分十进制
         * @return string IPv6
         * @throws Exception
         */
        static function IPv6DDNToCHN(string $DDN=''){
            $IPStr='';
            $IPArr=explode('.',$DDN);
            if (count($IPArr)!=16)
                throw new Exception('IP地址错误!');
            $IPArr=array_map(function ($val){
                return sprintf('%02s',dechex($val));
            },$IPArr);
            for ($Key=0;$Key<16;)
                $IPStr.=$IPArr[$Key++].$IPArr[$Key++].':';
            return rtrim(strtoupper($IPStr),':');
        }
    }
