<?php
    include 'connect.php';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Curd Operation</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">

</head>
<body>
  <div class="container  my-5">
    <h1 class="text-center text-primary">Simple Core PHP CRUD Operation.</h1>
    <button class="btn btn-primary text-end"><a href="index.php" class="text-light">Add user</a></button>
    <table class="table">
      <thead>
        <tr>
          <th scope="col">S no.</th>
          <th scope="col">Name</th>
          <th scope="col">Email</th>
          <th scope="col">Mobile</th>
          <th scope="col">Password</th>
          <th scope="col">Action</th>
        </tr>
      </thead>
      <tbody>
        <?php
            $sql="SELECT * FROM `crud`";
            $result=mysqli_query($con, $sql);
            if ($result) {
                // $row=mysqli_fetch_assoc($result);
                // echo $row['name'];
                while ($row=mysqli_fetch_assoc($result)) {
                    $id=$row['id'];
                    $name=$row['name'];
                    $email=$row['email'];
                    $mobile=$row['mobile'];
                    $password=$row['password'];
                    
                    echo '<tr>
                            <th scope="row">'.$id.'</th>
                            <td>'.$name.'</td>
                            <td>'.$email.'</td>
                            <td>'.$mobile.'</td>
                            <td>'.$password.'</td>
                            <td>
                            <a href="update.php?updateid='.$id.'" class="text-light"><button class="btn btn-primary">Update</button></a>
                            <a href="delete.php?deleteid='.$id.'" class="text-light"><button class="btn btn-danger">Delete</button></a>  
                            </td>
                        </tr>';
                }
            };
        ?>
      </tbody>
    </table>
  </div>
</body>
</html>