package com.vulnprint.controller;

import com.vulnprint.service.ReportDataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class RepGenRestController {

    @Autowired
    private ReportDataService reportDataService;

    @GetMapping("/repGenApi/{pentestId}")
    public ResponseEntity<?> getReportGenerationData(@PathVariable Long pentestId) {
        try {
            Map<String, Object> data = reportDataService.getReportGenerationData(pentestId);
            return ResponseEntity.ok()
                    .header("Cache-Control", "no-cache, no-store, must-revalidate")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .body(data);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal Server Error: " + e.getMessage()));
        }
    }
}
