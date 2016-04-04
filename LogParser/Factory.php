<?php

namespace LogParser;

class Factory
{

  protected $parser;
  protected $reports;

  public function __construct()
  {
    $this->parser = new LogParser();
    $this->reports = new Reports();
    $this->readFile();
  }

  public function readFile()
  {
    $lines = file('apache.log', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $n_lines = count($lines);
    $this->reports->setNumbersOfEntries($n_lines);

    foreach ($lines as $line) {
        try {
          //print_r($this->parser->parse($line));
          $this->reports->checkEntry($this->parser->parse($line));
        } catch(Exception $e) {
          //echo 'Exception: '. $e->getMessage(). "\n";
        }
    }

  }

  public function getResults()
  {
    return $this->reports->getResults();
  }

}
