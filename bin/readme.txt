Fields To Be Stashed
_time 
host 
columns.serial 
columns.vendor_id 
user* 
src_asset_tag 
dest_asset_tag 
user_priority 
rule* 
src*

|stats values(*) as * by host,columns.vendor_id

|eval rule_attack_tactic_technique=


`risk_score_user(low,low,user)`
risk_object_type="user"
risk_object=$object$
risk_rule_impact="$impact$"
risk_rule_confidence="$confidence$"
risk_rule_impact_num
risk_rule_confidence_num
risk_modifier_count_user
user_category
risk_score

|collect index=risk
