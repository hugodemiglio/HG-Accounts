<?php

/**
 * HGAccounts Class
 *
 * PHP 5
 *
 * Version 1.0.0
 *
 * HGAccounts : A very easy social login. For small applications.  (http://accounts.hgbrasil.com)
 * Copyright 2011, Hugo Demiglio (Brazilian Project)
 *
 * @copyright     Copyright 2011, Hugo Demiglio, hugodemiglio@gmail.com
 * @link          http://accounts.hgbrasil.com (HGAccounts)
 */

/* Start PHP Session */
session_start();

/* Inlude configuration file */
include 'configuration.php';

/* Create instance of class */
$HG = new HGAccounts($salt, $client_id, $client_id_secret, $service_root_url);

class HGAccounts {
/**
 * Salt key for decrypt data
 *
 * @var string
 * @access public
 */
  var $salt = '';
  
/**
 * Client ID for HG Accounts Authentication
 *
 * @var string
 * @access public
 */
  var $client_id = '';

/**
 * Client ID Secret to check authentication from HG Accounts
 *
 * @var string
 * @access public
 */
  var $client_id_secret = '';
  
/**
 * Your application root URL
 *
 * @var string
 * @access public
 */
  var $service_root_url = '';
  
/**
 * GET data
 *
 * @var array
 * @access public
 */
  var $get = null;
  
/**
 * Session data
 *
 * @var array
 * @access public
 */
  var $session = null;
  
/**
 * Construct class
 *
 * @param string $salt salt, string $client_id Client ID, string $client_id_secret Client ID Secret, string $service_root_url URL
 * @return void
 * @access public
 */
  function __construct($salt = null, $client_id = null, $client_id_secret = null, $service_root_url = null){
    $this->salt = $salt;
    $this->client_id = $client_id;
    $this->client_id_secret = $client_id_secret;
    $this->service_root_url = $service_root_url;
    
    $this->get = $_GET;
    $this->session = $_SESSION;
    
    $this->service_login_url = 'http://'.$_SERVER['HTTP_HOST'].str_replace('index.php', '', $_SERVER['SCRIPT_NAME']);
  }

/**
 * Descruct class
 *
 * @return void
 * @access public
 */
  function __destruct(){
    $_SESSION = $this->session;
  }
  
/**
 * Decode string
 *
 * @param string encoded
 * @return string decrypted
 * @access public
 */
  function decode($string = null){
    $string = base64_decode($string);
    $keys = str_split('ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvxyz@1234567890.');
    $salt = str_split($this->salt);
    if(!empty($string)) $string = str_split($string);
    if(is_array($string)) {
      $i = 0; foreach($string as $key){
        $replace_key = array_search($key, $salt);
        if(strlen($replace_key) > 0) $string[$i] = $keys[$replace_key];
        $i++;
      }
    }
    $data = explode('|', implode('', $string));
    if(count($data) > 0) foreach($data as $key => $value){
      $value = explode('[', $value);
      $data[@$value[0]] = @$value[1];
      unset($data[$key]);
    }
    return $data;
  }
  
/**
 * Redirect user to
 *
 * @param string $location location to, string $method = header method for redirect (header/meta_refresh)
 * @return void
 * @access public
 */
  function redirect($location = '', $method = 'header'){
    if($method == 'header') header("Location: ".$location);
    else echo '<meta http-equiv="refresh" content="0;url='.$location.'" />';
  }
  
/**
 * Write session data
 *
 * @param string $name key of session, string $value for session
 * @return boolean
 * @access public
 */
  function write($name = null, $value){
    $this->session[$name] = $value;
    if(isset($this->session[$name]) AND $this->session[$name] == $value) return true;
    return false;
  }
  
/**
 * Read session data
 *
 * @param string $name key of session
 * @return string session data if success, else boolean false
 * @access public
 */
  function read($name = null){
    if(isset($this->session[$name])) return $this->session[$name];
    return false;
  }
  
/**
 * Delete session data
 *
 * @param string $name key of session
 * @return boolean
 * @access public
 */
  function delete($name = null){
    if(isset($this->session[$name])) unset($this->session[$name]);
    if(!isset($this->session[$name])) return true;
    return false;
  }
  
/**
 * Make login
 *
 * @return void
 * @access public
 */
  function login(){
    if(isset($this->get['back_to'])) $this->write('redirect', $this->get['back_to']);
    
    $ok = 0;
    if(!$this->ifLogged()){
      if(isset($this->get['auth'])) {
        $data = $this->decode($this->get['auth']);
        
        if(isset($data['expire_at']) AND $data['expire_at'] >= date("U")){
          if(isset($data['client_id_secret']) AND $data['client_id_secret'] == $this->client_id_secret){
            $this->write('user', array('name' => $data['name'], 'email' => $data['email'], 'gender' => (($data['gender'] == 'male') ? 'masculino' : 'feminino'), 'method' => $data['method'], 'expire_at' => $data['expire_at']));
            $ok = 1;
            if($this->read('redirect')) $this->redirect($this->read('redirect'));
            else $this->redirect($this->service_root_url);
          }
        }
        
      }
    } else {
      $ok = 1;
      $this->redirect($this->service_root_url);
    }
    if($ok == 0) $this->redirect("http://accounts.hgbrasil.com/?client_id=".$this->client_id."&redirect=".$this->service_login_url);
  }
  
/**
 * Check user login
 *
 * @return boolean (true if logged, false if not)
 * @access public
 */
  function ifLogged(){
    if($this->read('user')) {
      $user = $this->read('user');
      if($user['expire_at'] >= date("U")) return true;
      else $this->logout(true);
    }
    return false;
  }
  
/**
 * Protect file forcing login
 *
 * @param string $login_url path to login
 * @access public
 */
  function restrict($login_url = '/login/'){
    $this->write('redirect', $_SERVER['REQUEST_URI']);
    if(!$this->ifLogged()) $this->redirect($login_url);
  }
  
/**
 * Make user logout
 *
 * @param boolean $force force delete sessions
 * @return boolean
 * @access public
 */
  function logout($force = false){
    if($force OR $this->ifLogged()){
      $this->delete('user');
    }
    $this->redirect("http://accounts.hgbrasil.com/logout?client_id=".$this->client_id);
  }
  
}

/* Get user data */
$user = $HG->read('user');

/* Funciton to print_r alias */
function pr($array = array()){
  echo '<pre>';
  print_r($array);
  echo '</pre>';
}

?>