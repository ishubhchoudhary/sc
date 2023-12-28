<!doctype html>
<html lang="en">
  <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">
    
    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.14.3/dist/umd/popper.min.js" integrity="sha384-ZMP7rVo3mIykV+2+9J3UJ46jBk0WLaUAdn689aCwoqbBJiSnjAK/l8WvCWPIPm49" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.1.3/dist/js/bootstrap.min.js" integrity="sha384-ChfqqxuZUCnJSK3+MXmPNIyE6ZbWh2IMqE241rYiqJxyMiZ6OW/JmZQ5stwEULTy" crossorigin="anonymous"></script>
    
    <title>Codeignator CRUD</title>
  </head>
  <body>
        <!-- As a link -->
    <nav class="navbar navbar-dark bg-dark">
        <a class="navbar-brand" href="#">CODEIGNATOR</a>
    </nav>

    <div class="container ">
        <br>
        <br>

        <!-- Button trigger modal -->
        <button type="button" class="btn btn-primary " data-toggle="modal" data-target="#exampleModal">
        Add
        </button>

        <!-- Modal -->
        <div class="modal fade " id="exampleModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
            <div class="modal-dialog" role="document">
                <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="exampleModalLabel">Modal title</h5>
                    <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                    <span aria-hidden="true">&times;</span>
                    </button>
                </div>
                <div class="modal-body">
                    <form method="post" action="<?php echo site_url('CrudController/create')?>">
                        <div class="form-group">
                            <label >Name</label>
                            <input type="text" class="form-control" name="name"  placeholder="Enter name">
                        </div>
                        <div class="form-group">
                            <label >Email</label>
                            <input type="text" class="form-control" name="email"  placeholder="Enter email">
                        </div>
                        <div class="form-group">
                            <label >Birtdate</label>
                            <input type="date" class="form-control" name="birthdate"  placeholder="Enter birthdate">
                        </div>
                        <div class="form-group">
                            <label >Contact</label>
                            <input type="text" class="form-control" name="contactNo"  placeholder="Enter contact">
                        </div>
                        <button type="submit" class="btn btn-primary" value="save">Submit</button>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                    <button type="button" class="btn btn-primary">Save changes</button>
                </div>
                </div>
            </div>
        </div>
        <table class="table ">
            <thead class="thead-dark">
                <tr>
                    <th scope="col">#</th>
                    <th scope="col">Name</th>
                    <th scope="col">Email</th>
                    <th scope="col">Birthdate</th>
                    <th scope="col">Contact</th>
                    <th scope="col">Action</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach($result as $row) { ?>
                <tr>
                    <!-- <th scope="row"></th> -->
                    <td><?php echo $row->id; ?></td>
                    <td><?php echo $row->name; ?></td>
                    <td><?php echo $row->email; ?></td>
                    <td><?php echo $row->birthdate; ?></td>
                    <td><?php echo $row->contactNo; ?></td>
                    <td><a href="<?php echo site_url('CrudController/edit');?>/<?php echo $row->id; ?>">Edit</a>  || 
                    <a href="<?php echo site_url('CrudController/delete');?>/<?php echo $row->id; ?>">Delete</a></td>
                </tr>
                <?php } ?>
            </tbody>
        </table>

    </div>
  </body>
</html>