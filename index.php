<?php
date_default_timezone_set('America/Los_Angeles');

// autoload Classes
spl_autoload_register(
    function( $classname ) {
        require_once str_replace( '\\', DIRECTORY_SEPARATOR, $classname ) . '.php';
    }
);

$factory = new \LogParser\Factory;
$result = $factory->getResults();

include('template.php');

?>
