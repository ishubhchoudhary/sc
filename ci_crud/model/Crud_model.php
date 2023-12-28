<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Crud_model extends CI_Model{

    public function __construct(){
        $this->load->database();
    }

    public function createDate(){
        $data = array(
            'name' => $this->input->post('name'),
            'email' => $this->input->post('email'),
            'birthdate' => $this->input->post('birthdate'),
            'contactNo' => $this->input->post('contactNo')
        );
        $this->db->insert('ci_crud', $data);
    }

    public function getAllData(){
        $query = $this->db->query('SELECT * FROM ci_crud');
        return $query->result();
    }

    public function getData($id){
        $query = $this->db->query('SELECT * FROM ci_crud WHERE `id` =' .$id);
        return $query->row();
    }

    public function updateData($id){
        $data = array(
            'name' => $this->input->post('name'),
            'email' => $this->input->post('email'),
            'birthdate' => $this->input->post('birthdate'),
            'contactNo' => $this->input->post('contactNo')
        );
        $this->db->where('id', $id);
        $this->db->update('ci_crud', $data);

    }

    public function deleteData($id){
        $this->db->where('id', $id);
        $this->db->delete('ci_crud');

    }
}
