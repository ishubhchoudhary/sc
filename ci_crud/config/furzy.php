<?php
// autoload.php start
    $autoload['libraries'] = array('database', 'email','session','form_validation','user_agent','Myclass','image_lib');
    $autoload['helper'] = array('url','form','custom','cookie');
    $autoload['model'] = array('common_model','cart_model','wishlist_model','url','menu_model');
// autoload.php end

// custom_helper.php start
    // <?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');
    function print_pre($data)
    { 
       echo "<pre>";print_r($data);echo "</pre>";       
    }
   
    function print_ex($data)
    { 
       echo "<pre>";print_r($data);echo "</pre>";exit();       
    }

    function base_admin()
    { 
       return base_url()."admin/";       
    }

    function csrf_field()
    { 
       $ci =& get_instance();
       $csrf = array(
             'name' => $ci->security->get_csrf_token_name(),
             'hash' => $ci->security->get_csrf_hash()
             );      
       return '<input type="hidden" name="'.$csrf['name'].'" value="'.$csrf['hash'].'" />';       
    }

    function message()
    { 
       $ci =& get_instance();
       if($ci->session->flashdata('alert_message')){ 
          return '<div class="col-lg-8 col-md-8 col-sm-12 col-xs-12 col-lg-offset-2 col-md-offset-2 ">
                  <div class="alert alert-success alert-dismissable fade in radius-flat">
                    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
                    <strong> '.$ci->session->flashdata('alert_message').' </strong>
                  </div>
                </div>';
       } 
       if($ci->session->flashdata('error_message')){ 
          return '<div class="col-lg-8 col-md-8 col-sm-12 col-xs-12 col-lg-offset-2 col-md-offset-2 ">
                  <div class="alert alert-danger alert-dismissable fade in radius-flat">
                    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
                    <strong>'.$ci->session->flashdata('error_message').' </strong>
                  </div>
                </div>';
       }       
    }

    function hashcode($data)
    {
       return hash('sha512',$data);
    }

    function getVar($type)
    {
      $data['metal'] = [
          [ 'name' => '14K', 'value' => '14K' ],
          [ 'name' => '18K', 'value' => '18K' ],
          [ 'name' => 'PLATINUM', 'value' => 'PLATINUM' ],
      ];
  
      $data['color'] = [
          [ 'name' => 'Platinum', 'value' => 'Platinum' ],
          [ 'name' => 'Rose', 'value' => 'R,Rose' ],
          [ 'name' => 'White', 'value' => 'W,White' ],
          [ 'name' => 'Yellow', 'value' => 'Y,Yellow' ],
      ];
  
      $data['quality'] = [
          [ 'name' => 'PREMIUM  + - FG -VS1', 'value' => 'PREMIUM  + - FG -VS1' ],
          [ 'name' => 'PREMIUM  - FG -VS2-SI1', 'value' => 'PREMIUM  - FG -VS2-SI1' ],
          [ 'name' => 'PREFERRED - FG-SI1-SI2', 'value' => 'PREFERRED - FG-SI1-SI2' ],
          [ 'name' => 'VALUE - JK - SI', 'value' => 'VALUE - JK - SI' ],
      ];
      
  
      $var = (!empty($data[$type])) ? $data[$type] : [];
      return  $var;
    }

// custom_helper.php end

//---------------------  Route -----------------------------//
$route['login'] = 'login';
$route['logout'] = 'login/logout';
$route['login-pop'] = 'login/login_pop';
$route['login-submit'] = 'login/login_submit';
$route['register'] = 'login/signup';
$route['signup-submit'] = 'login/signup_submit';
$route['subscribe-submit'] = 'login/subscribe_submit';
$route['cart-delete/:any/:num'] = 'mycart/delete_cart';

//---------------------  Route -----------------------------//

// Login.php controller start

function login_submit() {
    $secret='6LdfwOciAAAAAJRwbXTf62e0jDyMT4QxKD0H7hWw';
    $verifyResponse = file_get_contents('https://www.google.com/recaptcha/api/siteverify?secret='.$secret.'&response='.$this->input->post('g-recaptcha-response'));
    $responseData = json_decode($verifyResponse);
    if($responseData->success)
    {
        $this->form_validation->set_rules('username', 'Username', 'trim|required');
        $this->form_validation->set_rules('password', 'Password', 'trim|required');
        if ($this->form_validation->run() == FALSE) {
            $this->session->set_flashdata('error_message', 'Please Fill the Form Correctly!');
            redirect($_SERVER['HTTP_REFERER']);
        }
        $username = $this->input->post('username');
        $password = $this->input->post('password');
        // $data = array('user' => $username, 'pass' => hashcode($password));
        $data = array('user' => $username, 'pass' => $password);
        $result = $this->user_model->login_check($data);

        if(count(array_filter($result))) {
            if($result['0']->status=='1')
            {
                $this->session->set_userdata('user_id', $result['0']->customer_id);
                $this->session->set_userdata('user_email', $result['0']->email);
                $this->session->set_userdata('user_fullname', $result['0']->firstname.' '.$result['0']->lastname);
                $this->session->set_userdata('user_active', $result['0']->status);
                //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                $this->common_model->userLog($result['0']->customer_id);
                if ($this->input->post('remember')) {
                $hour = time()+3600*24*30;
                setcookie('username', $username, $hour);
                setcookie('password', $password, $hour);
                $cookie = array('name' => 'username', 'value' => $password, 'expire' => '86500',);
                $cookie1 = array('name' => 'password', 'value' => $username, 'expire' => '86500',);
                $this->input->set_cookie($cookie);
                $this->input->set_cookie($cookie1);
                }else {
                    set_cookie("username",'',time()-3600*24*30);
                    set_cookie("password",'',time()-3600*24*30);
                }

                if($this->input->post('referer')){
                    if(preg_match("/register$/", $this->input->post('referer'))){ 
                    redirect(base_url());
                    }else{
                    redirect(base_url());
                    }
                }

                redirect(base_url());
            }else {
                $this->session->set_flashdata('error_message', 'Please Verify Your Email!');
                redirect($_SERVER['HTTP_REFERER']);
            }

        }else{
            $this->session->set_flashdata('error_message', 'Username or Password is Incorrect!');
            redirect($_SERVER['HTTP_REFERER']);
        }
    }else{
        $this->session->set_flashdata('error_message', 'Please Fill the Captcha!');
        redirect($_SERVER['HTTP_REFERER']);
    }
}
function login_pop() {
    $message = '';
    $status = '0';
    $secret='6LdfwOciAAAAAJRwbXTf62e0jDyMT4QxKD0H7hWw';
    $verifyResponse = file_get_contents('https://www.google.com/recaptcha/api/siteverify?secret='.$secret.'&response='.$this->input->post('g-recaptcha-response'));
    $responseData = json_decode($verifyResponse);
    if($responseData->success){
         $this->form_validation->set_rules('username', 'Username', 'trim|required');
         $this->form_validation->set_rules('password', 'Password', 'trim|required');
         if ($this->form_validation->run() == FALSE) {
             $message = 'Please Fill the Form Correctly!';
         }
         $username = $this->input->post('username');
         $password = $this->input->post('password');
         $data = array('user' => $username, 'pass' => hashcode($password));
         $result = $this->user_model->login_check($data);
         if (count(array_filter($result))) 
         {
             $this->session->set_userdata('user_id', $result['0']->customer_id);
             $this->session->set_userdata('user_fullname', $result['0']->firstname.' '.$result['0']->lastname);
             $this->session->set_userdata('user_active', $result['0']->status);
             $this->session->set_userdata('user_email', $result['0']->email);
             //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
             $this->common_model->userLog($result['0']->customer_id);
             $status = '1';
         }else{
             $message = 'Username or Password is Incorrect!';
         }
     }else {
        $message = "Please Fill the Captcha";
     }
     echo json_encode(array('message' => $message, 'status' => $status));
}

function signup() {
    $data['title'] = '';
    $data['country'] = $this->common_model->selectAll('tbl_country');
    $data['states'] = $this->common_model->selectAll('tbl_state');
    $this->load->view('common/header', $data);
    $this->load->view('user/register', $data);
    $this->load->view('common/footer');
}
function signup_submit() {
    $secret='6LdfwOciAAAAAJRwbXTf62e0jDyMT4QxKD0H7hWw';
    $verifyResponse = file_get_contents('https://www.google.com/recaptcha/api/siteverify?secret='.$secret.'&response='.$this->input->post('g-recaptcha-response'));
    $responseData = json_decode($verifyResponse);
    if($responseData->success)
    {
        $this->form_validation->set_rules('firstname', 'firstname', 'trim|required');
        $this->form_validation->set_rules('lastname', 'lastname', 'trim|required');
        $this->form_validation->set_rules('password', 'password', 'trim|required');
        $this->form_validation->set_rules('passwordconfirm', 'Password Confirmation', 'trim|required|matches[password]');
        $this->form_validation->set_rules('email', 'Email', 'trim|required|valid_email');
        $this->form_validation->set_rules('emailconfirm','Email Confirmation','trim|required|matches[email]');
        if ($this->form_validation->run() == FALSE) {
            $this->session->set_flashdata('error_message', 'Please Fill the Form Correctly!');
            redirect(base_url('register'));
        }

        $firstname = $this->input->post('firstname');
        $lastname = $this->input->post('lastname');
        $email = $this->input->post('email');
        $phone = $this->input->post('phone');
        $password = $this->input->post('password');

        $where = array('email' => $email);
        $result = $this->common_model->selectWhere('tbl_customer',$where);
        if (count(array_filter($result))) {
            $this->session->set_flashdata('error_message', 'User Exist!');
            redirect(base_url('register'));
        }else{
            $data = array(
                'email' => $email, 
                'firstname' => $firstname, 
                'lastname' => $lastname,
                'phone' => $phone,
                'password' => hashcode($password), 
                'original_password' => $password, 
                'date_added' => date('Y-m-d H:i:s'), 
                'status' => 2, 
                'email_verify' => hashcode($email)
            );
            $user_id = $this->common_model->insertData('tbl_customer', $data);
            if ($user_id) {
                $this->session->set_flashdata('alert_message', 'Thank you for Registering with us!');
            }
            //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            $from = $this->config->item('smtp_user');
            //$to = SITE_EMAIL;
            $subject = 'New user registered';
            $this->email->set_newline("\r\n");
            $this->email->from($from);
            $this->email->to($email);
            $this->email->subject($subject);
            $data_email['user_name'] ='"'.$firstname.'" "'.$lastname.'"';
            $data_email['message'] = '<p>Thank you for registering with us.Your account is under review and will be activated within 12-24 hours.<br></p>';
            $msg = $this->load->view('email/registration_thankyou',$data_email, TRUE);
            $this->email->message($msg);
            $this->email->send();                
                    //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            $data=array(
                'id' => mt_rand(1111,9999), 
                'token_id' => mt_rand(000,999),
                'token' => hashcode($email)        
            );        
            $link=base_url().'verify-email?id='.$data['id'].'&token='.$data['token'].'&token_id='.$data['token_id'];

            $from = $this->config->item('smtp_user');
            $to = SITE_EMAIL;
            $subject = 'New User Registered';

            $this->email->set_newline("\r\n");
            $this->email->from($from);
            $this->email->to('shubham@gmail.com');
            $this->email->bcc('shubham@gmail.com');
            $this->email->subject($subject);

            $data_email['first_name'] = $firstname;
            $data_email['last_name'] = $lastname;
            $data_email['email'] = $email;
            $data_email['phone'] = $phone;
            $data_email['details_link'] = $link;

            $msg = $this->load->view('email/registration_email',$data_email, TRUE);
            $this->email->message($msg);
            if ($this->email->send()) {
                $this->session->set_flashdata('alert_message', 'Thanks For Registration. Please Verify Your Email!');
            }
        }
    }else {
        $this->session->set_flashdata('error_message', 'Please Fill the Captcha!');
        redirect(base_url('register'));
    }
}
function verify_email()
{
    $id=$this->input->get('id');
    $token_id=$this->input->get('token_id');
    $token=$this->input->get('token');
    if($id=='' || $token=='' || $token_id=='')
    {
     $message = 'Sorry! Invalid Token';
     $this->session->set_flashdata('error_message',$message);
     redirect(base_url('login'),'refresh'); 
    }           
    $where = array(
        'email_verify' => $token,
        'status' => 2
    );
    $result = $this->common_model->selectWhere('tbl_customer',$where);  
    if(count(array_filter($result))) 
    {            
        $data=array(
        'status'=>1,
        'email_verify' => ''
    );
        $where=array('customer_id'=>$result['0']->customer_id);
        $this->common_model->updateData('tbl_customer',$data,$where);
        $from = $this->config->item('smtp_user');
        //$to = SITE_EMAIL;
        $subject = 'Thank you from Diamonds';
        $email = $result['0']->email;
        $this->email->set_newline("\r\n");
        $this->email->from($from);
        $this->email->to($email);
        //$this->email->bcc('imran@braintreeproducts.com');
        $this->email->subject($subject);

        $link = base_url().'login';
        $firstname = $result['0']->firstname;
        $lastname = $result['0']->lastname;
        $user_name = ''.$firstname.' '.$lastname.'' ;
        $data_email['message_body'] = '<p>Dear '.$user_name.', Your account has been activated,please login veer.diamonds.<br></p>';

        $data_email['login'] ='<a class="mcnButton " title="Login" href="'.$link.'" 
        style="font-weight: bold;letter-spacing: -0.5px;line-height: 100%;text-align: center;text-decoration: none;color: #FFFFFF;">Login</a>';         
        $msg = $this->load->view('email/verified_thankyou_email',$data_email, TRUE);
        $this->email->message($msg);
        $this->email->send(); 
                //++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        $message = 'Email Successfully Verified! Customer will be notified through email';
        $this->session->set_flashdata('alert_message',$message);
        redirect(base_url('login'),'refresh');               
    }else {
        $message = 'Sorry! Invalid Token';
        $this->session->set_flashdata('error_message',$message);
        redirect(base_url('login'),'refresh'); 
    }         

}
function logout(){
    $this->session->unset_userdata('user_id');
    $this->session->unset_userdata('group_id');
    $this->session->unset_userdata('user_fullname');
    $this->session->unset_userdata('user_active');
    $this->session->unset_userdata('user_email');
        //Remove cookies
        //set_cookie("username", "", time() - 3600 * 24 * 30);
        //set_cookie("password", "", time() - 3600 * 24 * 30);
    redirect(base_url());
}
function resetPassword() 
{
    $config['page_head'] = 'Forgot Password';
    if ($this->input->post('forgetemail') != "") {
        $email = $this->input->post('forgetemail');
        $user_data = $this->common_model->get_entry_by_data('tbl_customer', true, array('email' => $email));
        // print_r($user_data);
        $username = $user_data['firstname']." ".$user_data['lastname'] ;
        if ($user_data) {
            $email_link = $this->ci_enc($email);
                // $config['wordwrap'] = TRUE;
                // $config['mailtype'] = 'html';
                // $config['charset'] = 'utf-8';
                // $config['priority'] = '1';
                // $config['crlf'] = "\r\n";
                // $config['newline'] = "\r\n";
                // $this->email->initialize($config);
                // $this->email->from(SITE_EMAIL, SITE_NAME);
                // $this->email->to($email);
                // $this->email->subject("Password Reset");

            $from = $this->config->item('smtp_user');
            $to = $email;
            $subject = 'Password Reset';

            $this->email->set_newline("\r\n");
            $this->email->from($from);
            $this->email->to($to);
            $this->email->subject($subject);
            $data_email['message_body'] = '<p>This is system generated email.</p><p>Please click on this link to reset password.</p>';
            $data_email['user_name'] = $email;                 
            $data_email['detail_link'] =base_url().'UserNewPassword/'.$email_link; 

            // $msg = $this->load->view('email/jewelry_details',$data_email, TRUE);
            $msg = $this->load->view('email/email_password',$data_email, TRUE);
            $this->email->message($msg);

            $data['message'] = "Sorry Unable to send email...";
            if ($this->email->send()) {
                $data['message'] = "Mail sent...";
            }
            $this->session->set_flashdata('alert_message', "Please check your email for password reset.");
            redirect('forgot-password');

        } else {
            $this->session->set_flashdata('error_message', "Invalid email id please check again.");
            redirect('forgot-password');
        }
    } else {
        $this->load->view('common/header');
        $this->load->view('user/forget', $config);
        $this->load->view('common/footer');
    }
}
// set new password
function new_password($id) {
    $email = $this->ci_dec($id);
    $config['page_head'] = 'Set New Password';
    $data['records'] = $this->common_model->get_entry_by_data('tbl_customer', true, array('email' => $email));
        //print_r($data['records']);
    if (!empty($data['records'])) {
            //echo "tarun";
        $this->form_validation->set_rules('newpassword', 'New Password', 'trim|required');
        $this->form_validation->set_rules('conpassword', 'Confirm Password', 'trim|required|matches[newpassword]');
        if ($this->form_validation->run() == TRUE) {
            $up_array = array('password' => hashcode($this->input->post('conpassword')),
                'original_password' => $this->input->post('conpassword'));
            $this->common_model->updateData('tbl_customer', $up_array, array('email' => $email));
            $this->session->set_flashdata('alert_message', 'Password has been updated successfully.');
            redirect(base_url('login'));
        } else {
                //$this->session->set_flashdata('error_message', 'Please Fill Required Form!');
            $this->load->view('common/header');
            $this->load->view('user/new_password', $config);
            $this->load->view('common/footer');                
        }
    } else {
            //$this->session->set_flashdata('error_message', 'Please Fill Required Form!');
        $this->load->view('common/header');
        $this->load->view('user/new_password', $config);
        $this->load->view('common/footer');
    }
}

function facebook_login() {
    require_once APPPATH . 'third_party/Facebook/autoload.php';
    $redirectUrl = base_url() . 'facebooklogin/';
    $fbPermissions = 'email';
    $app_id = fbAppId;
    $fb = new Facebook\Facebook(['app_id' => fbAppId, 'app_secret' => fbAppSecret, 'default_graph_version' => 'v2.2', ]);
    $helper = $fb->getRedirectLoginHelper();
    try {
        $accessToken = $helper->getAccessToken();
    }
    catch(Facebook\Exceptions\FacebookResponseException $e) {
        echo 'Graph returned an error: ' . $e->getMessage();
        redirect(base_url('login'));
    }
    catch(Facebook\Exceptions\FacebookSDKException $e) {
        echo 'Facebook SDK returned an error: ' . $e->getMessage();
        redirect(base_url('login'));
    }
    if (!isset($accessToken)) {
        redirect(base_url('login'));
    }
        // Logged in
    $oAuth2Client = $fb->getOAuth2Client();
    $tokenMetadata = $oAuth2Client->debugToken($accessToken);
    $tokenMetadata->validateAppId($app_id);
    $tokenMetadata->validateExpiration();
    if (!$accessToken->isLongLived()) {
        try {
            $accessToken = $oAuth2Client->getLongLivedAccessToken($accessToken);
        }
        catch(Facebook\Exceptions\FacebookSDKException $e) {
            echo "<p>Error getting long-lived access token: " . $helper->getMessage() . "</p>\n\n";
            redirect(base_url('login'));
        }
    }
    $_SESSION['fb_access_token'] = (string)$accessToken;
    try {
        $response = $fb->get('/me?fields=id,first_name,last_name,email,gender,locale,picture', (string)$accessToken);
    }
    catch(Facebook\Exceptions\FacebookResponseException $e) {
        echo 'Graph returned an error: ' . $e->getMessage();
        redirect(base_url('login'));
    }
    catch(Facebook\Exceptions\FacebookSDKException $e) {
        echo 'Facebook SDK returned an error: ' . $e->getMessage();
        redirect(base_url('login'));
    }
    $user = $response->getGraphUser();
    $userData['oauth_provider'] = 'facebook';
    $userData['oauth_uid'] = $user['id'];
    $userData['first_name'] = $user['first_name'];
    $userData['last_name'] = $user['last_name'];
    $userData['email'] = $user['email'];
    $userData['gender'] = $user['gender'];
    $password = 'jewelsfb@123';
    $result = $this->user_model->social_login($user['email']);
    if (count(array_filter($result))) {
        if ($result['0']->auth_provider == 'facebook') {
            $this->session->set_userdata('user_id', $result['0']->CD_USER_ID);
            $this->session->set_userdata('group_id', $result['0']->CD_GROUP_ID);
            $this->session->set_userdata('user_fullname', $result['0']->NM_USER_FULLNAME);
            $this->session->set_userdata('user_active', $result['0']->FL_USER_ACTIVE);
                //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            $this->common_model->userLog($result['0']->CD_USER_ID);
            redirect(base_url('diamond'));
        } else {
            $this->session->set_flashdata('alert_message', 'Email Already Exist!');
            redirect(base_url('login'));
        }
    } else {
        $data = array('CD_GROUP_ID' => 3, 'SN_USERNAME' => $user['email'], 'NM_USER_EMAIL' => $user['email'], 'NM_USER_FULLNAME' => $user['first_name'] . ' ' . $user['last_name'], 'USER_PASSWORD' => hashcode($password), 'SN_CREATED_BY' => 0, 'TS_CREATED_AT' => date('Y-m-d H:i:s'), 'FL_USER_ACTIVE' => 1, 'EMAIL_VERIFY' => '', 'auth_provider' => 'facebook',);
        $user_id = $this->common_model->insertData('tbl_user', $data);
        if ($user_id) {
            $data_details = array('CD_USER_ID' => $user_id, 'NM_COMPANY_NAME' => $user['first_name'] . ' ' . $user['last_name'], 'NM_PRIMARY_CONTACT_NAME' => $user['first_name'] . ' ' . $user['last_name'],);
            $this->common_model->insertData('tbl_user_details', $data_details);
            $this->session->set_userdata('user_id', $user_id);
            $this->session->set_userdata('group_id', 3);
            $this->session->set_userdata('user_fullname', $user['first_name'] . ' ' . $user['last_name']);
            $this->session->set_userdata('user_active', 1);
                //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            $this->common_model->userLog($user_id);
                //$this->session->set_flashdata('alert_message','Thank you for Registering with us!');

        }
        redirect(base_url('diamond'));
    }
    redirect(base_url());
}
function google_login() {
    include_once APPPATH . 'third_party/google-api-php-client-2/vendor/autoload.php';
    $clientId = GoogleClientId;
    $clientSecret = GoogleClientSecret;
    $redirectUrl = base_url() . 'google-login';
    $gClient = new Google_Client();
    $gClient->setApplicationName('Login to Veer Diamonds');
    $gClient->setClientId($clientId);
    $gClient->setClientSecret($clientSecret);
    $gClient->setRedirectUri($redirectUrl);
    $gClient->setScopes(array("https://www.googleapis.com/auth/plus.login", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/plus.me"));
    $google_oauthV2 = new Google_Service_Oauth2($gClient);
    $code = $this->input->get('code');
    if ($code != "") {
        $auth = $gClient->authenticate($code);
        $token = $gClient->getAccessToken();
        $this->session->set_userdata('token', $token);
    }
    if ($this->session->userdata('token') != "") {
        $gClient->setAccessToken($this->session->userdata('token'));
    }
    $user = $google_oauthV2->userinfo_v2_me->get();
    $password = 'jewelsg@123';
    $result = $this->user_model->social_login($user['email']);
    if (count(array_filter($result))) {
        if ($result['0']->auth_provider == 'google') {
            $this->session->set_userdata('user_id', $result['0']->CD_USER_ID);
            $this->session->set_userdata('group_id', $result['0']->CD_GROUP_ID);
            $this->session->set_userdata('user_fullname', $result['0']->NM_USER_FULLNAME);
            $this->session->set_userdata('user_active', $result['0']->FL_USER_ACTIVE);
                //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            $this->common_model->userLog($result['0']->CD_USER_ID);
            redirect(base_url('diamond'));
        } else {
            $this->session->set_flashdata('alert_message', 'Email Already Exist!');
            redirect(base_url('login'));
        }
    } else {
        $data = array('CD_GROUP_ID' => 3, 'SN_USERNAME' => $user['email'], 'NM_USER_EMAIL' => $user['email'], 'NM_USER_FULLNAME' => $user['name'], 'USER_PASSWORD' => hashcode($password), 'SN_CREATED_BY' => 0, 'TS_CREATED_AT' => date('Y-m-d H:i:s'), 'FL_USER_ACTIVE' => 1, 'EMAIL_VERIFY' => '', 'auth_provider' => 'google',);
        $user_id = $this->common_model->insertData('tbl_user', $data);
        if ($user_id) {
            $data_details = array('CD_USER_ID' => $user_id, 'NM_COMPANY_NAME' => $user['name'], 'NM_PRIMARY_CONTACT_NAME' => $user['name'],);
            $this->common_model->insertData('tbl_user_details', $data_details);
            $this->session->set_userdata('user_id', $user_id);
            $this->session->set_userdata('group_id', 3);
            $this->session->set_userdata('user_fullname', $user['name']);
            $this->session->set_userdata('user_active', 1);
                //+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            $this->common_model->userLog($user_id);
                //$this->session->set_flashdata('alert_message','Thank you for Registering with us!');

        }
        redirect(base_url('diamond'));
    }
    redirect(base_url());
}

function ci_enc($str){
   $new_str = strtr(base64_encode(addslashes(@gzcompress(serialize($str), 9))), '+/=', '-_.');
   return $new_str;  
}

function ci_dec($str){
   $new_str = unserialize(@gzuncompress(stripslashes(base64_decode(strtr($str, '-_.', '+/=')))));
   return $new_str;
}

function load_more_data()
{
  if(!$this->input->is_ajax_request()){ exit('No direct script access allowed'); }
    $page=$this->input->get('page');
    $per_page=$this->input->post('per_page');
   
    $where="diamond_id > 0 AND diamond_type = 1 AND total_price > 0";    
   
    $stock = $this->input->post('stock');  
   // print_ex($stock);     
    if(!empty($stock))
    {           
        $splitstock = explode(',', $stock); 
        $q1stock=implode("','",$splitstock);              
        $where .= " AND stock_id IN ('".$q1stock."')"; 
        //print_ex($where);            
    }     
    $shape = $this->input->post('checkbox');      
    if(!empty($shape))
    {
        $q1=implode("','",$shape);
        $where .= " AND shape_filter IN ('".$q1."')";
    }   
     $color = $this->input->post('color');                  
     if(!empty($color))
     {
         $color_array=array("D", "E", "F", "G", "H", "I", "J", "K", "L", "M");
         $color_array=$this->find_range($color,$color_array);
         $q2=implode("','",$color_array);
         $where .= " AND color IN ('".$q2."')";           
     }      
     $checkboxcut = $this->input->post('cut');                
     if(!empty($checkboxcut))
     {         
        $array_va=array("Ideal","Excellent", "Very Good", "Good", "Fair");
        $checkboxcut_range=$this->find_range($checkboxcut,$array_va);
        if(in_array('Round',  $shape))
        {
          if($checkboxcut=='Ideal;Fair') {
            $checkboxcut_range[]='NA';
          }
          $qcut = implode("','", $checkboxcut_range);
          $where .= " AND cut_full IN ('".$qcut."')";
        }                  
     }     
     $checkboxpolish = $this->input->post('polish');                
     if(!empty($checkboxpolish))
     {            
          $array_va=array("Excellent", "Very Good", "Good", "Fair");
          $checkboxpolish_range=$this->find_range($checkboxpolish,$array_va);

          if($checkboxpolish=='Excellent;Fair') {
              $checkboxpolish_range[]='NA';
          }

          $qpolish = implode("','", $checkboxpolish_range);
          $where .= " AND polish_full IN ('".$qpolish."')";      
     }         
     $checkboxsymm = $this->input->post('symmetry');                
     if(!empty($checkboxsymm))
     {           
        $array_va=array("Excellent", "Very Good", "Good", "Fair");
        $checkboxsymm_range=$this->find_range($checkboxsymm,$array_va);

         if($checkboxsymm=='Excellent;Fair') {
            $checkboxsymm_range[]='NA';
        }

        $qsymm = implode("','", $checkboxsymm_range);
        $where .= " AND symmetry_full IN ('".$qsymm."')";     
     }     
     $checkboxClarity = $this->input->post('clarity');
     if(!empty($checkboxClarity))
     {       
        $clarity_va=array("FL","IF","VVS1","VVS2","VS1","VS2","SI1","SI2","SI3","I1","I2","I3");
        $checkboxClarity=$this->find_range($checkboxClarity,$clarity_va);
       
        $qClarity = implode("','", $checkboxClarity);
        $where .= " AND grade IN ('".$qClarity."')";
     }   
     $checkboxFlour = $this->input->post('fluorescence');
     if(!empty($checkboxFlour))
     {         
        $array_va=array("None", "Faint", "Medium", "Strong","Very Strong");
        $checkboxFlour=$this->find_range($checkboxFlour,$array_va);

        $qFlour = implode("','", $checkboxFlour);
        $where .= " AND fluor_full IN ('".$qFlour."')";      
     }
    $range = $this->input->post('size');
    $split = explode(';', $range);
    $split1 = @$split['0'];    
    $split2 = @$split['1'];
    if($split2=='6'){
      $split2 = '200';
    }     
    if(!empty($range))
    {        
      $where .= " AND weight BETWEEN ('".$split1."') AND ('".$split2."')";     
    }     
    $total = $this->input->post('price');
    $splittotal = explode(';', $total);
    $splittotal1 = $splittotal['0'];
    $splittotal2 = @$splittotal['1'];    
    if(!empty($total))
    {
       $where .= " AND total_price BETWEEN (".$splittotal1.") AND (".$splittotal2.")";
    }
    $cert = $this->input->post('cert');      
    if(!empty($cert))
    {      
        $q1=implode("','",$cert); 
        $where .= " AND lab_filter IN ('".$q1."')";
    }
    //print_ex($where);

    $records_count = $this->diamond_model->diamond_count($where);

   // print_ex($this->db->last_query());
    $data['records_count'] =$records_count['0']->diamond_count;  
    //print_ex($this->input->get());  
    $per_page= ($per_page) ? $per_page : 100 ;
    $config['base_url'] = base_url().'load-more-diamond';
    $config['total_rows'] = $data['records_count'];
    $config['per_page'] = $per_page;
    $config['page_query_string']=true;
    $config['query_string_segment'] = 'page';
    $config['cur_tag_open'] = '<a class="active paginate_button current">';
    $config['cur_tag_close'] = '</a>';
    $config['next_link'] = '>';
    $config['prev_link'] = '<';
    $config['num_links'] = 2;
    $config['first_link'] = false;
    $config['last_link'] = false;
    
    $page= ($page) ? $page : 0 ;
    $this->pagination->initialize($config);
    $page_link=$this->pagination->create_links();

    $records = $this->diamond_model->diamond_list_limit($where,$per_page,$page);
   // print_ex($records);
    echo json_encode(array('records'=>$records,'page_link'=>$page_link,'total_records'=>$data['records_count']));
}
function diamond_details()
{
    $inventory_id = $this->uri->segment(2);  
    $image_array=array();
    $sample_image_array=array();
    $image_link=array();
    $video_array=array();
    $video_link=array();
    $certificate_array=array();
    $where = 'diamond_id = '."'".$inventory_id."'";      
    $records = $this->diamond_model->diamond_list($where);
    //echo $this->db->last_query(); die;
    if(count($records))
    {
      if($records['0']->diamond_image!="")
      {
        if(checkLink($records['0']->diamond_image)=='200')
        {
          if(preg_match("/png|jpg|jpeg|gif$/", $records['0']->diamond_image)){ 
            $image_array[]=$records['0']->diamond_image;
          }else{
            $image_link[]=$records['0']->diamond_image;
          }
        }
      }
      if(!count($image_array) && !count($image_link))
      {
          $file='assets/images/shape/'.$records['0']->shape_full.'.jpg';            
          if(file_exists($file)){
              $sample_image_array[]=base_url().$file;
          }else{
              $image_array[]=base_url().'assets/images/shape/No_image.jpg';
          } 
      }
      if($records['0']->diamond_video!="")
      {
        if(checkLink($records['0']->diamond_video)=='200'){
          $video_link[]=$records['0']->diamond_video;
        }
      }
      if($records['0']->report_filename!="")
      {
        if(checkLink($records['0']->report_filename)=='200'){
          $certificate_array[]=$records['0']->report_filename;
        }
      }
      //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
      $crange1= number_format($records['0']->weight-0.20,2); 
      $crange2= number_format($records['0']->weight+0.20,2);
      $where1 = " weight BETWEEN (".$crange1.") AND (".$crange2.")";

      $shape[]=$records['0']->shape;
      if($records['0']->shape=='RBC')
      {            
        $shape[]='Round';
        $shape[]='ROUND';              
      }

      $s1=implode("','",$shape);
      $where1 .= " AND shape IN ('".$s1."')";

      $similar_records = $this->diamond_model->diamond_list_limit($where1,10,0);
      //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    }
    else
    {
      redirect(base_url().'diamond');
    } 
    //print_ex($similar_records);   
    $data= array(
        'records'=>$records,
        'similar_records'=>$similar_records,
        'image_array'=>$image_array,
        'sample_image_array'=>$sample_image_array,
        'video_array'=>$video_array,
        'certificate_array'=>$certificate_array,
        'image_link'=>$image_link,
        'video_link'=>$video_link
    );
    //print_ex($data);
    $data['page_head'] = 'Diamond Details';     

    $this->load->view('common/header',$data);
    $this->load->view('diamond/diamond_details',$data);
    $this->load->view('common/footer');
}

function add_cart()
{     
  $user_id=$this->session->userdata('user_id');
  $diamond_id=$this->input->get('diamond_id');

  $where = 'diamond_id = '."'".$diamond_id."'";      
  $records = $this->diamond_model->diamond_list($where);
  
  foreach ($records as $row) 
  {
    $img=$this->list_image($row->NM_FOLDER_NAME,$row->stock_id);
    //print_pre($img);
    if(count(array_filter($img)))
    {
      $image_show = @$img['0'];
    }
    else
    {
      $image_show = shape_img($records['0']->shape);
    }

  }  
  if(count($records))
  {
    if($user_id!="")
    {
        $where=array('product_id'=>$diamond_id,'product_type'=>'diamond','customer_id'=>$user_id,);
        $cart_detail=$this->common_model->selectWhere('tbl_cart',$where);
        if(!count($cart_detail))
        {        
          $data=array(
            'product_id'=>$diamond_id,
            'stock_id'=>$records['0']->stock_id,
            'quantity'=>1,
            'product_type'=>'diamond',
            'price'=>$records['0']->total_price,
            'total_price'=>$records['0']->total_price,
            'name'=>$records['0']-> shape.' diamond',
            'description'=>$records['0']->shape.', '.$records['0']->cut_full.'-cut, '.$records['0']->color.'-color, '.$records['0']->grade.'-clarity diamond',
            'image'=>$image_show,
            'created_at'=>date('Y-m-d H:i:s'),
            'customer_id'=>$user_id,
          );
          $cart_id=$this->common_model->insertData('tbl_cart',$data);

        }
        $where1=array('customer_id'=>$user_id);
        $cart_details=$this->cart_model->get_cart($where1);  
        echo json_encode(array('records'=>$cart_details,'message'=>'ok'));

    }
    else
    { 
        $get_cookie=get_cookie('fc_cart_cookie');
        if($get_cookie!="")
        {
            $cart_data=array(
              'cookie_id'=>$get_cookie,
              'product_id'=>$diamond_id,
              'stock_id'=>$records['0']->stock_id,
              'quantity'=>1,
              'product_type'=>'diamond',
              'price'=>$records['0']->total_price,
              'total_price'=>$records['0']->total_price,
              'name'=>$records['0']->product_name,
              'description'=>$records['0']->product_short_description,
              'image'=>$image_show,
              'created_at'=>date('Y-m-d H:i:s'),
            );
            $this->common_model->insertData('tbl_cart_cookie',$cart_data);
        }
        else
        {
            $get_cookie=mt_rand().':'.userIp();
            set_cookie('fc_cart_cookie',$get_cookie,60*60*24*30);
            $cart_data=array(
              'cookie_id'=>$get_cookie,
              'product_id'=>$diamond_id,
              'stock_id'=>$records['0']->stock_id,
              'quantity'=>1,
              'product_type'=>'diamond',
              'price'=>$records['0']->total_price,
              'total_price'=>$records['0']->total_price,
              'name'=>$records['0']->product_name,
              'description'=>$records['0']->product_short_description,
              'image'=>$image_show,
              'created_at'=>date('Y-m-d H:i:s'),
            );
            $this->common_model->insertData('tbl_cart_cookie',$cart_data);
        }
        $where = array('cookie_id'=>$get_cookie);
        $cart_details = $this->cart_model->get_cart_cookie($where);
        echo json_encode(array('records'=>$cart_details, 'message'=>'ok', 'status'=>true));
    }
  }
  
}

class Mobile_api extends CI_Controller { 

    public function __construct()
    {
        parent::__construct();

        $this->load->model('user_model','user');

        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Authorization');
    }

    private function handleOptions() {
        if($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
            echo 'ok';exit;
        }
    }
    private function handlePost() {
        return json_decode(file_get_contents("php://input"));
    }

    function login()
    {
        $this->handleOptions();
        $post = $this->handlePost();

        $message = '';
        $status = 0;
        $data_return = [];        

        if (!trim($post->username) && !trim($post->password)) {
            $message = 'Please Fill the Form Correctly!';
        }
        else {            
            $username = $post->username;
            $password = $post->password;
            $password = hashcode($password);

            $result = $this->db->query("SELECT * FROM tbl_customer WHERE email = '$username' AND password = '$password'")->result();

            if (!empty($result)) 
            {
                if($result['0']->status=='1') 
                {                   
                    $data_return['user_id'] = $result['0']->customer_id;
                    $data_return['user_type'] = '';
                    $data_return['user_fullname'] = $result['0']->firstname.' '.$result['0']->lastname;
                    $data_return['user_firstname'] = $result['0']->firstname;
                    $data_return['user_lastname'] = $result['0']->lastname;
                    $data_return['username'] = $result['0']->email;
                    $data_return['user_email'] = $result['0']->email;
                    $data_return['user_mobile'] = $result['0']->mobile;
                    $data_return['user_phone'] = $result['0']->phone;
                    $data_return['user_company'] = $result['0']->company;
                    $data_return['user_address'] = $result['0']->address;
                    $data_return['user_address2'] = $result['0']->address2;
                    $data_return['user_city'] = $result['0']->city;
                    $data_return['user_state'] = $result['0']->state;
                    $data_return['user_country'] = $result['0']->country;
                    $data_return['user_zip'] = $result['0']->zip;
                    $data_return['user_active'] = $result['0']->status;
                    $data_return['user_jbt_id'] = $result['0']->jbt;
                    $data_return['user_tax_id'] = $result['0']->taxid;
                    $data_return['user_website'] = $result['0']->website_url;
                    $data_return['user_year_business'] = $result['0']->years_in_business;
                    $data_return['user_buy_group'] = $result['0']->buyinggroups;

                    $this->common_model->userLog($result['0']->customer_id, 1);
                    
                    $status = 1;
                }
                else {
                    $message = 'Please Verify Your Email!';
                }
            } else {
                $message = 'Username or Password is Incorrect!';
            }
        } 

        echo json_encode(['message' => $message, 'status' => $status, 'data' => $data_return]);
    } 
    
    function signup() 
    {
        $this->handleOptions();
        $post = $this->handlePost();

        $message = '';
        $status = 0;
        $data_return = array();

        $sales_person = $post->salesperson;
        $username = $post->username;
        $email = $post->username;
        $country = $post->country;
        $mobile = $post->mobile;
        $first_name = $post->firstName;
        $last_name = $post->lastName;
        $password = $post->password;
        $company_name = $post->companyName;

        $website_url = $post->website;
        $address = $post->address;
        $address2 = $post->address2;
        $city = $post->city;
        $country = $post->country;
        $state = $post->state;
        $phone = $post->phone;
        $jbt = $post->jbt;
        $taxid = $post->taxid;
        $yearsinbusiness = $post->yearsinbus;
        $buyinggroups = $post->buyinggroups;
        $zip = $post->zip;        

        if (trim($username) =='' || trim($first_name) =='' || trim($password) =='') {
            $message = 'Please Fill the Form Correctly!';
        } 
        else {

            if($first_name == $last_name) {
                $message = 'First and last name Can not be same!';
            }
            else {              
                $result = $this->db->query("SELECT * FROM tbl_customer WHERE email = '$email' ")->result();

                if (!empty($result)) {
                    $message = 'Email already Exists!';
                } else {
                    $data = [
                        'email' => $email, 
                        'firstname' => $first_name, 
                        'lastname' => $last_name,
                        'company' => $company_name,
                        'website_url'=> $website_url,
                        'phone' => $phone,
                        'mobile' => $mobile,
                        'jbt' => $jbt,
                        'taxid' => $taxid,
                        'address' => $address,
                        'address2' => $address2,
                        'city' => $city,
                        'state' => $state,
                        'country' => $country,
                        'zip' => $zip,
                        'years_in_business' => $yearsinbusiness,
                        'buyinggroups' => $buyinggroups,
                        'password' => hashcode($password), 
                        'original_password' => $password, 
                        'date_added' => date('Y-m-d H:i:s'), 
                        'status' => 2, 
                        'email_verify' => hashcode($email)
                    ];                    
                    
                    $user_id = $this->common_model->insertData('tbl_customer', $data);
                    if ($user_id) {     

                        $message = 'Thanks For Registration. Please Verify Your Email!';   
                        $status = 1;
                        
                        $this->email->from(SITE_EMAIL, SITE_NAME);
                        $this->email->to(SITE_EMAIL);
                        $this->email->subject("New User Registered");
                        
                        $data_email['message_body'] = '<p>This mail is generated from website. A new user has registered with us.<br>
                            <b>Customer Name: </b>'.$first_name.'  '.$last_name.' <br>
                            <b>Customer Email: </b>'.$email.' <br>
                            <b>Company Name: </b>'.$company_name.' <br>
                            <b>Customer website_url: </b>'.$website_url.'<br>
                            <b>Customer phone: </b>'.$phone.'<br>
                            <b>Customer mobile: </b>'.$mobile.'<br>
                            <b>Customer zip: </b>'.$zip.'<br>
                            <b>Customer jbt: </b>'.$jbt.'<br>
                            <b>Customer taxid: </b>'.$taxid.'<br>
                            <b>Customer address: </b>'.$address.'<br>
                            <b>Customer address2: </b>'.$address2.'<br>
                            <b>Customer city: </b>'.$city.'<br>
                            <b>Customer state: </b>'.$state.'<br>
                            <b>Customer country: </b>'.$country.'<br>
                            <b>Customer years_in_business: </b>'.$yearsinbusiness.'<br>
                            <b>Customer buyinggroups: </b>'.$buyinggroups.'<br>
                            </p>';         

                        $msg = $this->load->view('email/jewelry_details',$data_email, TRUE);
                        $this->email->message($msg);
                        $this->email->send();                
                        //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                        $data=array(
                                'id' => mt_rand(1111,9999), 
                                'token_id' => mt_rand(000,999),
                                'token' => hashcode($email)        
                            );        
                        $link=base_url().'verify-email?id='.$data['id'].'&token='.$data['token'].'&token_id='.$data['token_id'];
                        
                        $this->email->from(SITE_EMAIL, SITE_NAME);
                        $this->email->to($email);
                        $this->email->subject("Thank you from Veer Diamonds");
                        $data_email['message_body'] = '<p>Thank you for creating an online account with Veer Diamonds</p>';
             
                        $data_email['detail_link'] ='<a class="mcnButton " title="Verify Email" href="'.$link.'" 
                      style="font-weight: bold;letter-spacing: -0.5px;line-height: 100%;text-align: center;text-decoration: none;color: #FFFFFF;">Verify Email</a>'; 

                        $msg = $this->load->view('email/jewelry_details',$data_email, TRUE);
                        $this->email->message($msg);
                        $this->email->send();
                    }
                }
            }            
        }
        echo json_encode(array('message' => $message, 'status' => $status, 'data' => $data_return));
    }

    function forgot_password()
    {
        $this->handleOptions();
        $post = $this->handlePost();

        $message = '';
        $status = 0;
        $data_return = array();

        $email = $post->username;

        if(trim($email) != '') 
        {
            $result = $this->db->query("SELECT * FROM tbl_customer WHERE email = '$email' ")->result();
            if (!empty($result)) {
                $email_link = $this->ci_enc($email);
                
                $this->email->from(SITE_EMAIL, SITE_NAME);
                $this->email->to($email);
                $this->email->subject("Password Reset");
                $data_email['message_body'] = '<p>This is system generated email.</p><p>Please click on this link to reset password.</p>';
         
                $data_email['detail_link'] ='<a class="mcnButton " title="Verify Email" href="'.base_url().'UserNewPassword/'.$email_link.'" 
              style="font-weight: bold;letter-spacing: -0.5px;line-height: 100%;text-align: center;text-decoration: none;color: #FFFFFF;">Click Here</a>';         

                $msg = $this->load->view('email/jewelry_details',$data_email, TRUE);
                $this->email->message($msg);
                $this->email->send();

                $message = 'Please check your email for password reset.';
                $status = 1;
                
            } else {
                $message = 'Invalid email id please check again.';
            }
        } else {
            $message = 'Please Fill the Form Correctly!';
        }
        echo json_encode(array('message' => $message, 'status' => $status, 'data' => $data_return));
    }

    function account_delete()
    {
        $this->handleOptions();
        $post = $this->handlePost();

        $message = '';
        $status = 0;

        $user_id = $post->userId;

        if(!empty($user_id)) 
        {
            $result = $this->db->query("SELECT * FROM tbl_customer WHERE customer_id = $user_id")->result();
            
            if (!empty($result)) {
                $this->checkDemo($result['0']->email);

                $data = [
                    'user_type' => '', 
                    'salesman_id' => '', 
                    'email' => $result['0']->email, 
                    'mobile' => $result['0']->mobile, 
                    'first_name' => $result['0']->firstname, 
                    'last_name' => $result['0']->lastname, 
                    'password' => $result['0']->password,
                    'ext_no' => '',
                    'deleted_at' => date('Y-m-d H:i:s'), 
                ];
                $this->db->insert('tbl_account_deletion', $data);                
                //----------------------------------------------------------------------
                $this->db->delete('tbl_customer', ['customer_id' => $user_id]);
                $this->db->delete('tbl_cart', ['customer_id' => $user_id]);
                $this->db->delete('tbl_wishlist', ['customer_id' => $user_id]);
                $this->db->delete('tbl_user_log', ['CD_USER_ID' => $user_id]);
                //----------------------------------------------------------------------

                $this->email->from(SITE_EMAIL, SITE_NAME);
                $this->email->to($result['0']->email);
                $this->email->subject("Account deletion request");
                $data_email['message_body'] = '<p><b>Dear '.$result['0']->firstname.' '.$result['0']->lastname.'</b></p>
                    <p>Thanks for being a member of <a href="https://veer.diamonds/">veer.diamonds/</a>
                    <br>As per your request we have removed all data related to your account.</p>';

                $msg = $this->load->view('email/jewelry_details',$data_email, TRUE);
                $this->email->message($msg);
                $this->email->send();

            }
        }
        echo json_encode([
                'message' => 'Thanks for being a member of '.SITE_NAME, 
                'status' => 1, 
                'data' => []
        ]);
    }

    private function checkDemo($email) {
        if($email == 'sufiyan@braintreeproducts.com') {
            echo json_encode([
                'message' => 'Thanks for being a member of '.SITE_NAME, 
                'status' => 1, 
                'data' => []
            ]);
            exit;
        }
    }
    
    function contact_info()
    {
        $message = '';
        $status = 1;

        $info = array (
            'company_name' => 'VEER',
            'company_address' => '151W 46th Street, Suite 900A, New York, NY 10036',
            'email' => SITE_EMAIL,
            'phone' => SITE_PHONE,
            'fax' => '',
            'whatsapp' => '',
            'website' => 'https://veer.diamonds',
            'facebook' => 'https://www.facebook.com/veer.diamonds',
            'twitter' => '',
            'instagram' => 'https://www.instagram.com/veer.diamonds/',
            'googlemap' => '',
        );
    
        echo json_encode(array('message' => $message, 'status' => $status, 'data' => $info));
    }    

    function country_list()
    {
        $message = '';
        $status = 1;

        $countries = $this->common_model->selectAll('countries');
        $states = $this->common_model->selectAll('states');

        echo json_encode(array('message' => $message, 'status' => $status, 'data' => [ 'country' => $countries, 'state' => $states ]));
    }    

    function profile_update()
    {
        $this->handleOptions();
        $post = $this->handlePost();

        $status = 0;
        $message = '';

        $user_id = $post->userId;
        $user_email = $post->email;
        $user_firstname = $post->firstname;
        $user_lastname = $post->lastname;
        $user_address = $post->address;
        $user_address2 = $post->address2;
        $user_city = $post->city;
        $user_state = $post->state;
        $user_country = $post->country;
        $user_mobile = $post->mobile;
        $user_phone = $post->phone;
        $user_company = $post->companyName;
        //$user_salesman = $post->salesmanName;
        $user_jbtId = $post->jbtId;
        $user_taxId = $post->taxId;
        $user_zip = $post->zip;
        $user_yearsinbus = $post->yearsinbus;
        $user_website = $post->website;

        $data = [
            'email' => $user_email, 
            'firstname' => $user_firstname, 
            'lastname' => $user_lastname,
            'company' => $user_company,
            'website_url'=> $user_website,
            'phone' => $user_phone,
            'mobile' => $user_mobile,
            'jbt' => $user_jbtId,
            'taxid' => $user_taxId,
            'address' => $user_address,
            'address2' => $user_address2,
            'city' => $user_city,
            'state' => $user_state,
            'country' => $user_country,
            'zip' => $user_zip,
            'years_in_business' => $user_yearsinbus,
        ];

        $where = array('customer_id' => $user_id);
        $this->common_model->updateData('tbl_customer',$data,$where);

        $status = 1;
        $message = 'Profile Updated Successfully!';


        echo json_encode(array('message' => $message, 'status' => $status, 'data' => array()));
    }    
    function password_update()
    {
        $this->handleOptions();
        $post = $this->handlePost();

        $status = 0;
        $message = '';

        $user_id = $post->user_id;
        $old_password = $post->old_password;
        $new_password = $post->new_password;
        $confirm_password = $post->confirm_password;
        $old_password = hashcode($old_password);

        $existdata = array(
            'password' => $old_password, 
            'customer_id' => $user_id
        );
        $check_old_password = $this->common_model->selectWhere('tbl_customer', $existdata);
        if(!empty($check_old_password)) 
        {
            $data = array('password' => hashcode($new_password));
            $where = array('customer_id' => $user_id);
            $this->common_model->updateData('tbl_customer', $data, $where);

            $message = 'Password updated successfully!';
            $status = 1;
        }else{
            $message = 'Old Password is not Correct!';
            $status = 0;            
        }


        echo json_encode(array('message' => $message, 'status' => $status, 'data' => array()));
    }

    function delete_wishlist()
    {
        $this->handleOptions();
        $post = $this->handlePost();

        $status = 0;
        $message = '';

        $user_id = $post->userId;
        $wishlist_id = $post->wishlistId;

        $wishlist_id = explode(',', $wishlist_id);

        foreach ($wishlist_id as $key => $value) {
            $where = [
                'wishlist_id' => $value,
                'customer_id' => $user_id
            ];
            $this->common_model->deleteData('tbl_wishlist',$where);
        }


        $status = 1;
        echo json_encode([
            'message' => $message, 
            'status' => $status, 
            'data' => []
        ]);

    }
    
    function ci_enc($str){
       $new_str = strtr(base64_encode(addslashes(@gzcompress(serialize($str), 9))), '+/=', '-_.');
       return $new_str;  
    }

    function ci_dec($str){
       $new_str = unserialize(@gzuncompress(stripslashes(base64_decode(strtr($str, '-_.', '+/=')))));
       return $new_str;
    }
}

// --------------------------model------------------------------------------------------

class Common_model extends CI_Model {

	// +++++++ For Selection Of one Row +++++++++
	function selectOne($table,$column,$value)
	{
		$this->db->select('*');
		$this->db->from($table);
		$this->db->where($column,$value);
		$query=$this->db->get();
		return $query->result();
	}
	// +++++++ For Selection Of All Row +++++++++
	function selectAll($table)
	{
		$this->db->select('*');
		$this->db->from($table);		
		$query=$this->db->get();
		return $query->result();
	} 
	
	// +++++++ For Selection Of All Row +++++++++
	function selectAllarray($table)
	{
		$this->db->select('*');
		$this->db->from($table);		
		$query=$this->db->get();
		return $query->result_array();
	} 

	// +++++++ For Select Where (multiple condition in array) +++++++++
	function selectWhere($table,$where)
	{
		$this->db->select('*');
		$this->db->from($table);
		$this->db->where($where);
		$query=$this->db->get();
		return $query->result();
	}
	// +++++++ For Select Where (multiple condition in array with order by condition) +++++++++
	function selectWhereorderby($table,$where,$col,$condition)
	{
		$this->db->select('*');
		$this->db->from($table);
		$this->db->where($where);
		$this->db->order_by($col,$condition);
		$query=$this->db->get();
		return $query->result();
	}
	// +++++++ For Select Where In (array) +++++++++
	function selectWhereIn($table,$column,$wherein)
	{
		$this->db->select('*');
		$this->db->from($table);
		$this->db->where_in($column,$wherein);
		$query=$this->db->get();
		return $query->result();
	}
	// +++++++ For Select Join +++++++++
	function selectJoin($table1,$column1,$table2,$column2)
	{
		$this->db->select('*');
		$this->db->from($table1);
		$this->db->join($table2, $table1.'.'.$column1.' = '.$table2.'.'.$column2);
			//$this->db->where_in($column,$wherein);
		$query=$this->db->get();
		return $query->result();
	}
	// +++++++ For Select Join Where+++++++++
	function selectJoinWhere($table1,$column1,$table2,$column2,$where)
	{
		$this->db->select('*');
		$this->db->from($table1);
		$this->db->join($table2, $table1.'.'.$column1.' = '.$table2.'.'.$column2);
		$this->db->where($where);
		$query=$this->db->get();
		return $query->result();
	}
	// +++++++ Select max Table +++++++++++++++++
	function selectMax($table,$column)
	{
		$this->db->select_max($column);
		$query = $this->db->get($table); 
		return $query->result();
	}
	// +++++++ Select min Table +++++++++++++++++
	function selectMin($table,$column)
	{
		$this->db->select_min($column);
		$query = $this->db->get($table); 
		return $query->result();
	}
	// +++++++ To Insert Data To Table +++++++++
	function insertData($table,$data)
	{
		$this->db->insert($table,$data);
		return $this->db->insert_id();
	}
	// +++++++ To Update Data To Table +++++++++
	function updateData($table,$data,$where)
	{
		$this->db->update($table,$data,$where);			
	}
	// +++++++ To Delete Data To Table +++++++++
	function deleteData($table,$where)
	{	
		$this->db->where($where);
		$this->db->delete($table);
			//$this->db->affected_rows();
	}	
	function updateCounter($table,$data,$where)
	{
		$this->db->query("UPDATE ".$table." SET ".$data." = ".$data." + 1 WHERE ".$where."");
	}

	//++++++++ User log ++++++++++++++++++++++++
	function userLog($user_id)
	{
		if ($this->agent->is_browser())
		{
			$browser = $this->agent->browser().' '.$this->agent->version();
		}
		elseif ($this->agent->is_robot())
		{
			$browser = $this->agent->robot();
		}
		elseif ($this->agent->is_mobile())
		{
			$browser = $this->agent->mobile();
		}
		else
		{
			$browser = 'Unidentified';
		}
		$platform = $this->agent->platform();
		$ip_address = $_SERVER['REMOTE_ADDR'];

		$data=array(
			'CD_USER_ID'=>$user_id,
			'SN_IPADDRESS'=>$ip_address,
			'SN_BROWSER'=>$browser,
			'SN_OS'=>$platform,
			'TS_CREATED_AT'=>date('Y-m-d H:i:s'),
		);
		$this->db->insert('tbl_user_log',$data);
			//return $this->db->insert_id();
	}     
	//+++++++++++++Last login +++++++++++++++++++
	function last_login($vendor_id)
	{
		$this->db->select('UL.TS_CREATED_AT');
		$this->db->from('tbl_user_log UL');	
		
		$this->db->where('UL.CD_USER_ID',$vendor_id);
		$this->db->order_by('UL.CD_LOG_ID', 'DESC');
		$this->db->limit(1,1);
		$query=$this->db->get();
		return $query->result();
	}  
	function get_entry_by_data($table_name, $single = false, $data = array(),$select="",$order_by='',$orderby_field='',$limit='',$offset=0) {
		




		if (empty($data)){

			$id = $this->input->post('CD_ITEM');

			if ( ! $id ) return false;

			$data = array('CD_ITEM' => $id);		

		}  

		if(!empty($limit)){
			$this->db->limit($limit,$offset);
		}   

		if(!empty($order_by) && !empty($orderby_field)){

			$this->db->order_by($orderby_field,$order_by);
		}

		$this->db->cache_on();
		$query = $this->db->get_where($table_name, $data);

		$res = $query->result_array();

        //echo $this->db->last_query();exit;

		if (!empty($res)) {

			if ($single)
				return $res[0]; 
			else
				return $res;
		}

		else
			return false;

	}

	function url_slug($string)
	{
        //Unwanted:  {UPPERCASE} ; / ? : @ & = + $ , . ! ~ * ' ( )
		$string = strtolower($string);
        //Strip any unwanted characters
		$string = preg_replace("/[^a-z0-9_\s-]/", " ", $string);
        //Clean multiple dashes or whitespaces
		$string = preg_replace("/[\s-]+/", "-", $string);
        //Convert whitespaces and underscore to dash
		$string = preg_replace("/[\s_]/", "-", $string);
        //$string =substr_replace($string ,"",-1);//Last dashes remove
		return $string;
	}

	function update_entry($table_name, $data, $where)
	{
		return $this->db->update($table_name, $data, $where);
	}

	function getCatNameSlug($slug){
		$query=$this->db->query("select c.category_id,c.category_name,cd.category_slug from tbl_category as c 
			join tbl_category_description as cd on c.category_id=cd.category_id where cd.category_slug='".$slug."' ");
		$result=$query->result();
		if(count($result)){
			return @ucwords($result['0']->category_name);
		}else{
			return "";
		}
	}
	function categoryMeta($slug){
		$query=$this->db->query("select category_meta_title,category_meta_keyword,category_meta_description 
			from tbl_category_description as cd 
			where cd.category_slug='".$slug."' ");
		$result=$query->result();
	}

	function getCategory($parent_id) {
		$query = $this->db->query("SELECT c.category_id,c.category_name,cd.category_slug 
			FROM tbl_category c
			join tbl_category_description cd on cd.category_id=c.category_id
			where c.parent_category ='".$parent_id."' and c.category_status='active'");
		return $query->result();
	}

	function getCategoryMenu() { 

		$category = $this->getCategory(0);

		foreach ($category as $row) 
		{
			$html='';
			$sub_category = $this->getCategory($row->category_id); 
			
			$html.='<li class="nav-item dropdown">';
			$html.='<a class="nav-link" href="'.base_url().'jewelry/'.$row->category_slug.'"  id="navbarDropdown" role="button"   aria-haspopup="true" aria-expanded="false">
			'.$row->category_name.' </a>';
			if(!empty($sub_category)) {
				$html.='<div class="dropdown-menu" aria-labelledby="navbarDropdown">';
				$html.=' <div class="mega-menu custom-container">';
				
				$html.=' <ul class="multi-list">';
				foreach ($sub_category as $subcat) {
					$html.='<li>';
					$html.=' <a href="'.base_url().'jewelry/'.$row->category_name.'/'.$subcat->category_slug.'">'.$subcat->category_name.'</a>';
					$html.=' </li>';
				}
				$html.=' </ul>';
			

				$html.=' </div>';  
				$html.='</div>';

				$html.=' </li>';

			}
			echo $html;
		}
	}
    // ++++++++ To validate login +++++++++++
    function login_check($data)
    {
            $this->db->select('customer_id,firstname,lastname,status,email');
            $this->db->from('tbl_customer');
            $this->db->where('email',$data['user']);
            $this->db->where('original_password',$data['pass']);
            $query=$this->db->get();
            return $query->result();
    }

    function facebook_login($email)
    {
        $this->db->select('*');
                $this->db->from('tbl_user');
        $this->db->where('NM_USER_EMAIL',$email);
        $this->db->where('auth_provider','facebook');
        $query=$this->db->get();
                return $query->result();
    }
    function google_login($email)
    {
        $this->db->select('*');
                $this->db->from('tbl_user');
        $this->db->where('NM_USER_EMAIL',$email);
        $this->db->where('auth_provider','google');
        $query=$this->db->get();
                return $query->result();
    }

    function jewelry_list_limit($where,$limit='',$offset=0,$order='')
    {  
        if($where!=""){        
          $where="WHERE ".$where;
        }      
        if($order!=""){
          $order_query="ORDER BY ".$order;
        }
        else{
          $order_query="ORDER BY product_id ";
        }    
        $query = $this->db->query("select * from v_product ".$where." group by product_id ".$order_query." LIMIT  ".$offset." , ".$limit);
        return $query->result();
    }

    function diamond_count($where)
    {  
        $pQuery = $this->db->query("SELECT markup FROM tbl_pricing WHERE type ='diamond' AND markup_type ='percent' ");
        $pResult = $pQuery->result();
        $user_markup = (@$pResult['0']->markup) ? $pResult['0']->markup : 0;
  
        $where=" WHERE ".$where." "; 
        $data=array(
          'where'=>$where,
          'user_markup'=>$user_markup
        );
        $query = $this->db->query("CALL p_diamond_count(?,?)",$data);   
        mysqli_next_result($this->db->conn_id);
  
        return $query->result();
    } 
    function diamond_list_limit($where,$limit='',$offset=0,$order='')
    {  
        $pQuery = $this->db->query("SELECT markup FROM tbl_pricing WHERE type ='diamond' AND markup_type ='percent' ");
        $pResult = $pQuery->result();
        $user_markup = (@$pResult['0']->markup) ? $pResult['0']->markup : 0;
  
        $where=" WHERE ".$where." ";
        $group_by=" ";      
        if($order){
          $order_query=" ORDER BY ".$order;
        }else{
          $order_query=" ORDER BY shape_sort ASC,clarity_sort ASC,weight_sort ASC ";
        }      
        $data=array(
          'where'=>$where,
          'group_by'=>$group_by,
          'order_query'=>$order_query,
          'limit_st'=>' LIMIT  '.$offset.' , '.$limit,
          'user_markup'=>$user_markup,
          'markup_type'=>'',
          'select_st'=>'color,country,cash_price,cut_full,depth,diamond_id,diamond_image,diamond_video,fluor_full,grade,lab,lab_filter,lab_full,measurements,polish_full,report_filename,report_no,shade,shape,shape_filter,shape_full,stock_id,symmetry_full,table_d,cost_carat,total_price,weight,diamond_type,vendor_id'
        );
        $query = $this->db->query("CALL p_diamond(?,?,?,?,?,?,?)",$data);
        mysqli_next_result($this->db->conn_id);
        
        return $query->result();
    }
}


// --------------------------model------------------------------------------------------
// --------------------------view------------------------------------------------------

// <?php echo message(); ?>
// <section id="pageContent" class="page-content padding-two form-design">
//         <div class="container">
//             <div class="row cart-body">
//                <form class="form-horizontal" action="<?php echo base_url(); ?>login-submit" method="post">
//                 <?php echo csrf_field(); ?>
//                 <input type="hidden" value="<?php echo $this->input->get('referer'); ?>" name="referer">
//                     <div class="col-lg-4 col-md-4 col-sm-4 col-xs-12"></div>
//                    <div class="col-lg-4 col-md-4 col-sm-4 col-xs-12">                   
//                         <div class="">
//                             <div class="panel-heading padding-two text-center text-uppercase"><h4>Login</h4></div>
//                             <div class="panel-body">
//                                 <div class="form-group">
//                                     <div>
//                                     </div>
//                                 </div>
//                                 <div class="form-group">                                    
//                                     <div>
//                                         <input type="email" class="form-control radius-flat" id="username" name="username" placeholder="Email" required="">
//                                     </div>
//                                 </div>
//                                 <div class="form-group">                                    
//                                     <div>
//                                         <input type="password" data-toggle="validator"  class="form-control radius-flat" id="password" name="password" placeholder="Password" required="">
//                                     </div>
//                                 </div>    
//                                    <div class="form-group">
//                                     <label>
//                                                 <input type="checkbox" id="terms1" name="remember" <?php  //if(isset($_COOKIE['username'])){ echo "checked='ckecked'";}?> value="1" data-error="Before you wreck yourself">
//                                                 Remember me
//                                             </label>
//                          </div>                                 
//                                 <div class="form-group text-center">
//                                         <div>
//                                             <label>
//                                                 <a href="<?php echo base_url('forgot-password'); ?>"> Forgot Password</a><br>
//                                             </label>
//                                         </div>
//                                 </div>                                                      

//                            </div>
//                            <div>
//                             <button type="submit" class="btn btn-primary btn-block padding-two text-med radius-flat" onclick="return validateSignIn()">Sign In</button>
                            
//                            </div>
//                            <div class="help-block with-errors"></div>
//                         </div> 
//                         <label style="display: block;text-align: center;padding: 10px 0;"><a href="<?php echo base_url(); ?>register" class="text-center">Create Account</a></label>
//                    </div>
//                    <div class="col-lg-4 col-md-4 col-sm-4 col-xs-12"></div>
//                </form>

//             </div>
//     </div>
// </section>














?>