
function Comandos(valor)
{
  var text = "";
  switch (valor) {
    case "Borrar_Historial"     : text = "R.Borrar_Historial";break;
    case "Borrar_Base_de_datos" : text = "R.Borrar_Base_de_datos";break;
    case "Valores_de_fabrica"   : text = "R.Valores_de_fabrica";break;
    case "Nuevo_servidor"       : text = "R.Nuevo_servidor";break;
    case "Firmware"       : text = "F.Actualizar_Firmware";break;
    default                     : text = "R.No value found";
  }

  var param = {
      Comando: text//document.getElementById("Historial").value//,    			nombre: document.getElementById("boton1").value
    };
    $.ajax({
        type:'POST', //aqui puede ser igual get
        url: './include/command.php',//'funciones/mifuncion.php',//aqui va tu direccion donde esta tu funcion php
        data:param,
        //data: {id:1,otrovalor:'valor'},//aqui tus datos
        success:function(data){
            //lo que devuelve tu archivo mifuncion.php
       },
       error:function(data){
        //lo que devuelve si falla tu archivo mifuncion.php
       }
     });
}
