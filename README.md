# SA-RBA

## Dependencies
URL Toolbox: https://splunkbase.splunk.com/app/2734/

Semicircle Donut Chart Viz: https://splunkbase.splunk.com/app/4378/

Network Diagram Viz: https://splunkbase.splunk.com/app/4438/

Sankey Diagram - Custom Visualization:  https://splunkbase.splunk.com/app/3112/

Event Timeline Viz: https://splunkbase.splunk.com/app/4370/

## Note on proxy usage
azerty728 correctly pointed out in one of the previous issues that the genmitrelookup script runs just fine through a locally configured proxy when a single line (import os) is added to the underlying python script. That fix has been added and tested against these Splunk best practice for configuring a proxy:  https://docs.splunk.com/Documentation/Splunk/8.0.6/Admin/ConfigureSplunkforproxy OR https://docs.splunk.com/Documentation/Splunk/8.0.6/Admin/Serverconf.
