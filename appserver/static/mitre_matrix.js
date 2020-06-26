/**
 * The below is a custom table renderer for the content table. It highlights colors inside the cells.
 */
require([
    'underscore',
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/tableview',
    'splunkjs/mvc/simplexml/ready!'
], function(_, $, mvc, TableView) {

    /**
 * The below is a custom table renderer for the MITRE Map table.
 */
    var MitreMapTableRenderer = TableView.BaseCellRenderer.extend({
        canRender: function(cell) {
            return true;
        },
        render: function($td, cell) {
            var cellvalue = cell.value;

            if (cellvalue != null) {
                values = [];
                $.each(cellvalue, function(i, val) {
                    values[i] = val;

                });
                var celltext = values[0].split(" (")[0];
                var threat_groups=values[0].split(" (")[1];
                var colorhex = values[1];
                var bgcoloropacity = values[2];
                var tooltip = values[3];

                if (typeof(threat_groups) != "undefined") {
                    threat_groups = threat_groups.replace(")", "")
                    tooltip=tooltip+"<br />Threat Groups: "+threat_groups
                    $td.addClass("threat_group");
                }
                //if (tooltip && tooltip.search(/Selected: 0/i)==-1) {
                //    $td.addClass("selected");
                //}
                $td.attr( "style", "background-color: rgb(" + hexToRgb(colorhex) + "," + bgcoloropacity + ") !important;");


                $td.html(_.template('<span data-toggle="tooltip" data-placement="bottom" title="<%- tooltip%>"><%- celltext%></span>', {
                    tooltip: tooltip,
                    celltext: celltext

                }));

                $td.children().tooltip({ html: 'true' })
                    //console.log(mitre_technique+" "+mitre_technique_count_total)


            } else {
                $td.html(cell.value);
            }
        }
    });
    if (mvc.Components.get('mitremaptable')) {

        mvc.Components.get('mitremaptable').getVisualization(function(tableView) {
            // Register custom cell renderer, the table will re-render automatically
            tableView.addCellRenderer(new MitreMapTableRenderer());
        });
    }
});

function hexToRgb(hex) {
    var result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    var r = parseInt(result[1], 16),
        g = parseInt(result[2], 16),
        b = parseInt(result[3], 16)
    return result ? r + ',' + g + ',' + b : null;
}
