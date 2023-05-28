package com.prai.opa;

import com.fasterxml.jackson.annotation.*;

import javax.annotation.Generated;
import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
        "input"
})
@Generated("jsonschema2pojo")
public class BulkOPARequest implements Serializable
{

    @JsonProperty("input")
    private BulkOPAInput input;
    @JsonIgnore
    private Map<String, Object> additionalProperties = new LinkedHashMap<String, Object>();
    private final static long serialVersionUID = 1817343865301079127L;

    /**
     * No args constructor for use in serialization
     *
     */
    public BulkOPARequest() {
    }

    /**
     *
     * @param input
     */
    public BulkOPARequest(BulkOPAInput input) {
        super();
        this.input = input;
    }

    @JsonProperty("input")
    public BulkOPAInput getInput() {
        return input;
    }

    @JsonProperty("input")
    public void setInput(BulkOPAInput input) {
        this.input = input;
    }

    @JsonAnyGetter
    public Map<String, Object> getAdditionalProperties() {
        return this.additionalProperties;
    }

    @JsonAnySetter
    public void setAdditionalProperty(String name, Object value) {
        this.additionalProperties.put(name, value);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(BulkOPARequest.class.getName()).append('@').append(Integer.toHexString(System.identityHashCode(this))).append('[');
        sb.append("input");
        sb.append('=');
        sb.append(((this.input == null)?"<null>":this.input));
        sb.append(',');
        sb.append("additionalProperties");
        sb.append('=');
        sb.append(((this.additionalProperties == null)?"<null>":this.additionalProperties));
        sb.append(',');
        if (sb.charAt((sb.length()- 1)) == ',') {
            sb.setCharAt((sb.length()- 1), ']');
        } else {
            sb.append(']');
        }
        return sb.toString();
    }

    @Override
    public int hashCode() {
        int result = 1;
        result = ((result* 31)+((this.input == null)? 0 :this.input.hashCode()));
        result = ((result* 31)+((this.additionalProperties == null)? 0 :this.additionalProperties.hashCode()));
        return result;
    }

    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if ((other instanceof BulkOPARequest) == false) {
            return false;
        }
        BulkOPARequest rhs = ((BulkOPARequest) other);
        return (((this.input == rhs.input)||((this.input!= null)&&this.input.equals(rhs.input)))&&((this.additionalProperties == rhs.additionalProperties)||((this.additionalProperties!= null)&&this.additionalProperties.equals(rhs.additionalProperties))));
    }

}