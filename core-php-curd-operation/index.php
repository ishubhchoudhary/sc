<?php
    include "connect.php";
    if(isset($_POST['submit'])) {
        $name=$_POST['name'];
        $email=$_POST['email'];
        $mobile=$_POST['mobile'];
        $password=$_POST['password'];

        $sql="insert into `crud` (name,email,mobile,password) 
        values('$name', '$email', '$mobile', '$password')";

        $result=mysqli_query($con, $sql);
        if ($result) {
            //  echo "Data insert successfully";
            header('location:display.php');
        }else{
            die(mysqli_error($con));
        }

    };
?>
<!doctype html>
<html lang="en">
  <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
    
    <title>Crud Operation</title>
  </head>
  <body>
      <div class="container my-5">
        <form method="POST">
            <div class="mb-3">
                <label class="form-label"> Name </label>
                <input type="text" class="form-control" placeholder="Enter your name" name="name" autocomplete="off">
            </div>
            <div class="mb-3">
                <label class="form-label"> Email </label>
                <input type="text" class="form-control" placeholder="Enter your Email" name="email" autocomplete="off">
            </div>
            <div class="mb-3">
                <label class="form-label"> Mobile </label>
                <input type="text" class="form-control" placeholder="Enter your mobile number" name="mobile" autocomplete="off">
            </div>
            <div class="mb-3">
                <label class="form-label"> Password </label>
                <input type="text" class="form-control" placeholder="Enter your password" name="password">
            </div>
            <button type="submit" name="submit" class="btn btn-primary">Submit</button>
            <button class="btn btn-primary"><a href="display.php" class="text-light">Display users</a></button>

        </form>
    </div>
  </body>
</html>
