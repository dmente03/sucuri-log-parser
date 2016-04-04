<?php

namespace LogParser;

class Reports
{

  protected $total_number_of_entries;
  protected $errors = 0;
  protected $success = 0;
  protected $bad_requests = array();
  protected $files_requested_more = array();
  protected $most_popular_referers = array('itens' => array(), 'total' => 0);
  protected $top_user_agents = array('itens' => array(), 'total' => 0);
  protected $malicious_requests = array();
  protected $utils;
  protected $IDSInit;

  public function __construct(){
    $this->utils = new \LogParser\Utils;

    // Create instance of IDS malicious detection
    $init = \IDS\Init::init('/Applications/XAMPP/xamppfiles/htdocs/lab/log-parser/IDS/Config/Config.ini');
    $ids = new \IDS\Monitor($init);
    $this->IDS = $ids;
  }

  public function setNumbersOfEntries($number_entries = 0)
  {
    $this->total_number_of_entries = $number_entries;
  }

  public function checkEntry($entry = null)
  {
    // call detect malicious request method
    if($this->detectMaliciousRequest($entry)){
      return false;
    }

    // set success or error
    switch ($entry->status) {
      case '200':
      $this->filesMoreRequested($entry);
      $this->mostPopularReferers($entry);
      $this->topUserAgents($entry);
      $this->success++;
      break;

      case '400':
      $this->bad_requests[] = $entry;
      $this->errors++;
      break;

      case '404':
      $this->bad_requests[] = $entry;
      $this->errors++;
      break;

      case '408':
      $this->errors++;
      break;
    }
  }
  public function detectMaliciousRequest($entry = null)
  {
    $method = substr($entry->request, 0, 3);
    $request = str_replace(" HTTP/1.0", "", str_replace(" HTTP/1.1", "", str_replace($method,"", $entry->request)));

    $Query_String = explode("?", $request);
    $Query_String = explode("=", $Query_String[1]);

    $_request = array();
    $_request[$Query_String[0]] = $Query_String[1];

    $request = array(
        'REQUEST' => $_request
    );

    $result = $this->IDS->run($request);

    if (!$result->isEmpty()) {
     // Take a look at the result object
     //echo $result;
     $this->malicious_requests[] = $entry;
     return true;
    }
    return false;
  }

  public function filesMoreRequested($entry = null)
  {
    // set files requested
    $method = substr($entry->request, 0, 3);
    $page = str_replace(" HTTP/1.0", "", str_replace(" HTTP/1.1", "", str_replace($method,"", $entry->request)));

    if (!$this->utils->in_array_r($page, $this->files_requested_more)){
      array_push($this->files_requested_more, array('page' => $page, 'count' => 1, 'method' => $method));
    }
    else {
      for ($i=0; $i < count($this->files_requested_more); $i++) {
        if($this->files_requested_more[$i]['page'] == $page){
          $this->files_requested_more[$i]['count']++;
        }
      }
    }
  }

  public function mostPopularReferers($entry = null)
  {
    // set files requested
    $referer = $entry->HeaderReferer;

    if($referer == '-') return;

    if (!$this->utils->in_array_r($referer, $this->most_popular_referers['itens'])){
      array_push($this->most_popular_referers['itens'], array('referer' => $referer, 'count' => 1));
    }
    else {
      for ($i=0; $i < count($this->most_popular_referers['itens']); $i++) {
        if($this->most_popular_referers['itens'][$i]['referer'] == $referer){
          $this->most_popular_referers['itens'][$i]['count']++;
        }
      }
    }
    $this->most_popular_referers['total']++;
  }

  public function topUserAgents($entry = null)
  {
    // set files requested
    $userAgent = $entry->HeaderUseragent;

    if($userAgent == '') return;

    if (!$this->utils->in_array_r($userAgent, $this->top_user_agents['itens'])){
      array_push($this->top_user_agents['itens'], array('name' => $userAgent, 'count' => 1));
    }
    else {
      for ($i=0; $i < count($this->top_user_agents['itens']); $i++) {
        if($this->top_user_agents['itens'][$i]['name'] == $userAgent){
          $this->top_user_agents['itens'][$i]['count']++;
        }
      }
    }
    $this->top_user_agents['total']++;
  }

  public function getResults()
  {

    $result = array();
    $result['total_number_of_entries'] = $this->total_number_of_entries;
    $result['success'] = $this->success;
    $result['errors'] = $this->errors;
    $result['malicious_requests'] = count($this->malicious_requests);

    $result['files_requested_more'] = array();
    usort($this->files_requested_more, function($a, $b) {
        return $a['count'] - $b['count'];
    });
    $files_requested_more = array_reverse($this->files_requested_more);
    foreach ($files_requested_more as $file) {
      $file['percentual'] = substr($file['count']/$this->success*100, 0, 4);
      $file['page'] = htmlentities($file['page']);
      $result['files_requested_more'][] = $file;
    }

    usort($this->most_popular_referers['itens'], function($a, $b) {
        return $a['count'] - $b['count'];
    });
    $most_popular_referers = array_reverse($this->most_popular_referers['itens']);
    foreach ($most_popular_referers as $referer) {
      $referer['percentual'] = substr($referer['count']/$this->most_popular_referers['total']*100, 0, 4);
      $referer['referer'] = $referer['referer'];
      $result['most_popular_referers'][] = $referer;
    }

    usort($this->top_user_agents[itens], function($a, $b) {
        return $a['count'] - $b['count'];
    });
    $top_user_agents = array_reverse($this->top_user_agents['itens']);
    foreach ($top_user_agents as $user_agent) {
      $user_agent['percentual'] = substr($user_agent['count']/$this->top_user_agents['total']*100, 0, 4);
      $user_agent['name'] = $user_agent['name'];
      $result['top_user_agents'][] = $user_agent;
    }

    $result['malicious_requests'] = array();
    foreach ($this->malicious_requests as $request) {
      $item = array();
      $item['host'] = $request->host;
      $item['time'] = $request->time;
      $item['request'] = htmlentities($request->request);
      $result['malicious_requests'][] = $item;
    }

    return $result;

  }

}
