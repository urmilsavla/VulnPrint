package com.vulnprint.controller;

import com.vulnprint.service.ReportDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/reports")
public class ReportRestController {

    @Autowired
    private ReportDataService reportDataService;

    /**
     * @deprecated Use {@link #getMasterReportDataV2(Long)} instead.
     */
    @Deprecated
    @GetMapping("/master-data/{pentestId}")
    public ResponseEntity<?> getMasterReportData(@PathVariable Long pentestId) {
        try {
            Map<String, Object> data = reportDataService.getMasterReportDataV2(pentestId);
            return ResponseEntity.ok(data);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Internal Server Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @GetMapping("/master-api/{pentestId}")
    public ResponseEntity<?> getMasterReportDataV2(@PathVariable Long pentestId) {
        try {
            Map<String, Object> data = reportDataService.getMasterReportDataV2(pentestId);
            return ResponseEntity.ok()
                    .header("Cache-Control", "no-cache, no-store, must-revalidate")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .body(data);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Internal Server Error: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }
}
