resource "pingfederate_oauth_token_exchange_processor_policy" "wai" {
  policy_id            = local.policy_id
  name                 = "WAI Agent Transaction Exchange"
  actor_token_required = true

  attribute_contract = {
    extended_attributes = [
      for name in sort(tolist(local.transaction_attributes)) : {
        name = name
      }
    ]
  }

  processor_mappings = [
    {
      subject_token_processor = {
        id = pingfederate_idp_token_processor.subject.processor_id
      }

      subject_token_type = local.subject_token_type

      actor_token_processor = {
        id = pingfederate_idp_token_processor.spire_actor.processor_id
      }

      actor_token_type = local.actor_token_type

      # The first mapping deliberately proves the two cryptographic identities:
      # user_id    <- verified subject token
      # workload_id <- verified actor JWT-SVID subject
      #
      # AgentID and transaction metadata are intentionally not accepted as
      # trusted arbitrary request fields in this baseline.
      attribute_contract_fulfillment = {
        # PingFederate's TEPP contract always includes the core `subject`
        # attribute. Bind it to the validated subject-token ATM output.
        subject = {
          source = {
            type = "SUBJECT_TOKEN"
          }
          value = "user_id"
        }

        user_id = {
          source = {
            type = "SUBJECT_TOKEN"
          }
          value = "user_id"
        }

        workload_id = {
          source = {
            type = "ACTOR_TOKEN"
          }
          value = "sub"
        }

        scope = {
          source = {
            type = "SUBJECT_TOKEN"
          }
          value = "scope"
        }

        agent_id = {
          source = {
            type = "NO_MAPPING"
          }
        }

        agent_instance_id = {
          source = {
            type = "NO_MAPPING"
          }
        }

        transaction_id = {
          source = {
            type = "NO_MAPPING"
          }
        }

        transaction_purpose = {
          source = {
            type = "NO_MAPPING"
          }
        }
      }
    }
  ]
}
