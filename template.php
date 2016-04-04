
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">

    <title>HTTP log file read and report</title>

    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="bootstrap/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">

    <style>
    .btn-default {
      margin-bottom: 50px;
    }
    </style>
    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>

  <body>
    <div class="container">

      <h1>Results for reading the access log file</h1>
      <a class="btn btn-default" href="apache.log" role="button" target="_blank">Link to apache.log</a>

      <div class="panel panel-default">
        <!-- Default panel contents -->
        <div class="panel-heading">Requests</div>

        <!-- Table -->
        <table class="table">
          <thead>
            <th>Number of requests</th>
            <th>Number of success (200)</th>
            <th>Number of errors (400, 404, 408)</th>
            <th>Number of malicious requests</th>
          </thead>
          <tbody>
            <td><?php echo $result['total_number_of_entries']; ?></td>
            <td><?php echo $result['success']; ?></td>
            <td><?php echo $result['errors']; ?></td>
            <td><?php echo count($result['malicious_requests']); ?></td>
          </tbody>
        </table>
      </div>

      <div class="panel panel-default">
        <!-- Default panel contents -->
        <div class="panel-heading">Malicious request </div>

        <!-- Table -->
        <table class="table">
          <thead>
            <th>IP</th>
            <th>Time</th>
            <th>Request</th>
          </thead>
          <tbody>
            <?php foreach ($result['malicious_requests'] as $item): ?>
              <tr>
                <td><?php echo $item['host']; ?></td>
                <td><?php echo $item['time']; ?></td>
                <td><?php echo $item['request']; ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <div class="panel panel-default">
        <!-- Default panel contents -->
        <div class="panel-heading">Files more visited - Listing 20 from <?php echo count($result['files_requested_more']); ?></div>

        <!-- Table -->
        <table class="table">
          <thead>
            <th>File</th>
            <th>Qty</th>
            <th>(%)</th>
          </thead>
          <tbody>
            <?php foreach (array_slice($result['files_requested_more'], 0, 20) as $item): ?>
            <tr>
              <td><?php echo $item['page']; ?></td>
              <td><?php echo $item['count']; ?></td>
              <td><?php echo $item['percentual']; ?></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <div class="panel panel-default">
        <!-- Default panel contents -->
        <div class="panel-heading">Most popular referers - Listing 20 from <?php echo count($result['most_popular_referers']); ?></div>

        <!-- Table -->
        <table class="table">
          <thead>
            <th>Url</th>
            <th>Qty</th>
            <th>(%)</th>
          </thead>
          <tbody>
            <?php foreach (array_slice($result['most_popular_referers'], 0, 20) as $item): ?>
            <tr>
              <td><?php echo $item['referer']; ?></td>
              <td><?php echo $item['count']; ?></td>
              <td><?php echo $item['percentual']; ?></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

      <div class="panel panel-default">
        <!-- Default panel contents -->
        <div class="panel-heading">Top user-agents - Listing 20 from <?php echo count($result['top_user_agents']); ?></div>

        <!-- Table -->
        <table class="table">
          <thead>
            <th>User-agent</th>
            <th>Qty</th>
            <th>(%)</th>
          </thead>
          <tbody>
            <?php foreach (array_slice($result['top_user_agents'], 0, 20) as $item): ?>
            <tr>
              <td><?php echo $item['name']; ?></td>
              <td><?php echo $item['count']; ?></td>
              <td><?php echo $item['percentual']; ?></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>

    </div>

    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>

    <!-- Latest compiled and minified JavaScript -->
    <script src="bootstrap/js/bootstrap.min.js" integrity="sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS" crossorigin="anonymous"></script>

  </body>
</html>
